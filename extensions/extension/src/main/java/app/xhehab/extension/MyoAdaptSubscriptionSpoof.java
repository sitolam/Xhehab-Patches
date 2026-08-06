package app.xhehab.extension;

import android.content.Context;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * MyoAdapt unlock helpers.
 *
 * Real RC account state: core-access on main_sub (trial expired 2025-08-04).
 * Home paywall is driven by the backend session (coach.myoadapt), not only RC,
 * so RC spoofing is paired with a response rewrite on the session endpoints.
 *
 * Everything here must stay *surgical*. The gate endpoints (GetUserInfo in
 * particular) also carry the user's programs, workouts and schedule, and the app
 * is Fable/F# — its decoders are structural, so an unexpected key or a flipped
 * enum anywhere in the payload makes decoding throw and the screen bail out.
 * Only subscription-scoped values are touched, only when they already exist, and
 * nothing is ever inserted.
 */
public final class MyoAdaptSubscriptionSpoof {
    private static final String TAG = "MyoAdaptSpoof";
    private static final String PURCHASE = "2026-07-09T00:00:00Z";
    private static final String EXPIRE = "2035-07-09T00:00:00Z";
    private static final String PRODUCT = "main_sub";
    private static final String PLAN = "monthly-introductory-affiliate";

    /** Gate payloads are small; never buffer a whole training catalog. */
    private static final long PEEK_LIMIT = 512L * 1024L;

    private static final int KIND_NONE = 0;
    private static final int KIND_REVENUECAT = 1;
    private static final int KIND_BACKEND = 2;

    /** Subscription status values that must read as active. */
    private static final String[] INACTIVE_STATUSES = {
        "expired", "trial", "trialing", "cancelled", "canceled", "inactive",
        "lapsed", "none", "free", "unsubscribed", "paused"
    };

    private static volatile boolean installed = false;

    // ---- Diagnostic / forge (temporary R&D build) -----------------------------
    // The session-start action is gated server-side (HTTP 402). To learn the exact
    // success shape and prototype the rewrite without re-patching each attempt, this
    // build logs all /api/action/ traffic and applies "forge" rules read from the
    // app's own external files dir:
    //   <externalFilesDir>/forge/rules      lines: <urlSubstring>|<bodyFileName>
    //   <externalFilesDir>/forge/<bodyFile> canned 200 body returned for matches
    // Files are pushed with plain `adb push` (app-owned dir, no root). Absent/empty
    // config = plain pass-through, so shipping this build changes nothing until a
    // rule is pushed.
    private static volatile Context appContext = null;
    private static final String ACTION_MARKER = "/api/action/";

    private MyoAdaptSubscriptionSpoof() {}

    /**
     * Call from MainApplication.onCreate. Installs the OkHttp factory carrying the
     * subscription interceptor.
     *
     * Deliberately does not touch on-disk state: the session token lives in the same
     * MMKV store as everything else, and RC's cached CustomerInfo already goes through
     * the patched CustomerInfoFactory, so there is nothing to clear and clearing it
     * only logs the user out.
     */
    public static void install(Context context) {
        if (context != null) {
            appContext = context.getApplicationContext();
        }
        try {
            installOkHttpFactory();
        } catch (Throwable t) {
            Log.e(TAG, "installOkHttpFactory failed", t);
        }
    }

    private static void installOkHttpFactory() throws Exception {
        if (installed) return;
        final Class<?> provider =
                Class.forName("com.facebook.react.modules.network.OkHttpClientProvider");
        final Class<?> factoryIface =
                Class.forName("com.facebook.react.modules.network.OkHttpClientFactory");

        Object factory =
                Proxy.newProxyInstance(
                        factoryIface.getClassLoader(),
                        new Class<?>[] {factoryIface},
                        new InvocationHandler() {
                            @Override
                            public Object invoke(Object proxy, Method method, Object[] args)
                                    throws Throwable {
                                String name = method.getName();
                                if ("createNewNetworkModuleClient".equals(name)) {
                                    Method createBuilder =
                                            provider.getMethod("createClientBuilder");
                                    Object builder = createBuilder.invoke(null);
                                    // Application interceptor (NOT network): body is already
                                    // gunzipped. Network interceptors see raw gzip → binary garbage
                                    // and JSON rewrite never matches.
                                    Method addInterceptor =
                                            builder.getClass()
                                                    .getMethod(
                                                            "addInterceptor",
                                                            Interceptor.class);
                                    addInterceptor.invoke(builder, interceptor());
                                    Method build = builder.getClass().getMethod("build");
                                    return build.invoke(builder);
                                }
                                // Object methods reach the proxy too; returning null for
                                // hashCode() would NPE on unboxing.
                                if ("hashCode".equals(name)) {
                                    return System.identityHashCode(proxy);
                                }
                                if ("equals".equals(name)) {
                                    return args != null && args.length == 1 && proxy == args[0];
                                }
                                if ("toString".equals(name)) {
                                    return "MyoAdaptOkHttpClientFactory";
                                }
                                return null;
                            }
                        });

        Method setFactory =
                provider.getMethod("setOkHttpClientFactory", factoryIface);
        setFactory.invoke(null, factory);

        // Drop any client created before our factory
        for (String fieldName : new String[] {"sClient", "client"}) {
            try {
                Field f = provider.getDeclaredField(fieldName);
                f.setAccessible(true);
                f.set(null, null);
            } catch (NoSuchFieldException ignored) {
            }
        }
        installed = true;
        Log.i(TAG, "OkHttpClientFactory installed");
    }

    /**
     * Which rewrite, if any, applies to a URL.
     *
     * Everything else — catalogs, training payloads, media, telemetry — is passed
     * through untouched.
     */
    private static int payloadKind(String url) {
        if (url == null) return KIND_NONE;
        if (url.contains("revenuecat") || url.contains("/subscribers")) {
            return KIND_REVENUECAT;
        }
        if (!url.contains("myoadapt")) {
            return KIND_NONE;
        }
        // Backend session gate (confirmed: sub.status / isExpired on GetUserInfo)
        if (url.contains("GetUserInfo")
                || url.contains("LoginPassword")
                || url.contains("LoginSocial")
                || url.contains("SocialLogin")
                || url.contains("GetSubscription")
                || url.contains("SubActions/")) {
            return KIND_BACKEND;
        }
        return KIND_NONE;
    }

    public static Interceptor interceptor() {
        return new Interceptor() {
            @Override
            public Response intercept(Chain chain) throws java.io.IOException {
                final Request request = chain.request();
                final String url = String.valueOf(request.url());
                Response response = chain.proceed(request);

                final boolean action = url.contains(ACTION_MARKER);

                // Forge: turn a gated/failed action into a canned 200 success.
                // Runs before the isSuccessful() gate below because the whole point
                // is to rewrite the 402.
                if (action) {
                    try {
                        Response forged = maybeForge(response, url);
                        if (forged != null) {
                            return forged;
                        }
                    } catch (Throwable t) {
                        Log.w(TAG, "forge failed url=" + url + " err=" + t.getMessage());
                    }
                    // Diagnostic capture of the real request/response.
                    try {
                        logAction(request, response, url);
                    } catch (Throwable t) {
                        Log.w(TAG, "diag failed url=" + url + " err=" + t.getMessage());
                    }
                }

                final int kind = payloadKind(url);
                if (kind == KIND_NONE || !response.isSuccessful()) {
                    return response;
                }

                ResponseBody body = response.body();
                if (body == null) {
                    return response;
                }

                // Application interceptor: body is decompressed. peekBody copies
                // without consuming. Do not rebuild unless we actually rewrite
                // (avoids Content-Length / encoding mismatches).
                String text;
                try {
                    text = response.peekBody(PEEK_LIMIT).string();
                } catch (Throwable t) {
                    Log.w(TAG, "peekBody failed url=" + url + " err=" + t.getMessage());
                    return response;
                }

                if (text == null || text.isEmpty()) {
                    return response;
                }

                String rewritten =
                        kind == KIND_REVENUECAT ? rewriteRevenueCat(text) : rewriteBackend(text);
                if (rewritten == null || rewritten.equals(text)) {
                    return response;
                }

                Log.i(TAG, "rewrote subscription payload url=" + url);
                return response.newBuilder()
                        .removeHeader("Content-Encoding")
                        .removeHeader("Content-Length")
                        .body(ResponseBody.create(rewritten, body.contentType()))
                        .build();
            }
        };
    }

    // ---- Diagnostic / forge helpers -------------------------------------------

    private static File forgeDir() {
        Context ctx = appContext;
        if (ctx == null) return null;
        File ext = ctx.getExternalFilesDir(null);
        if (ext == null) return null;
        return new File(ext, "forge");
    }

    /**
     * If a forge rule matches this url, return a synthetic 200 response carrying the
     * canned body from the rule's file. Returns null when no rule matches (or the
     * config is absent), leaving the real response untouched.
     */
    private static Response maybeForge(Response response, String url) {
        File dir = forgeDir();
        if (dir == null) return null;
        File rules = new File(dir, "rules");
        if (!rules.isFile()) return null;

        String rulesText = readTextFile(rules);
        if (rulesText == null) return null;

        for (String line : rulesText.split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int bar = line.indexOf('|');
            if (bar <= 0) continue;
            String urlSubstring = line.substring(0, bar).trim();
            String bodyFile = line.substring(bar + 1).trim();
            if (urlSubstring.isEmpty() || bodyFile.isEmpty()) continue;
            if (!url.contains(urlSubstring)) continue;

            String body = readTextFile(new File(dir, bodyFile));
            if (body == null || body.isEmpty()) {
                // Rule staged but body not ready — leave the real response alone.
                return null;
            }
            Log.i(TAG, "FORGE match rule='" + urlSubstring + "' file=" + bodyFile
                    + " origCode=" + response.code() + " url=" + url);
            ResponseBody rb = response.body();
            okhttp3.MediaType type =
                    rb != null && rb.contentType() != null
                            ? rb.contentType()
                            : okhttp3.MediaType.parse("application/json; charset=utf-8");
            return response.newBuilder()
                    .code(200)
                    .message("OK")
                    .removeHeader("Content-Encoding")
                    .removeHeader("Content-Length")
                    .body(ResponseBody.create(body, type))
                    .build();
        }
        return null;
    }

    /** Log the full request + response of an action call, chunked past logcat's limit. */
    private static void logAction(Request request, Response response, String url) {
        String method = request.method();
        String reqBody = readRequestBody(request);
        String respBody = null;
        try {
            respBody = response.peekBody(PEEK_LIMIT).string();
        } catch (Throwable ignored) {
        }
        String tail = url.contains(ACTION_MARKER)
                ? url.substring(url.indexOf(ACTION_MARKER) + ACTION_MARKER.length())
                : url;
        Log.i(TAG, "ACTION " + method + " code=" + response.code() + " " + tail);
        logChunked("REQ[" + tail + "]", reqBody);
        logChunked("RESP[" + tail + "](" + response.code() + ")", respBody);
    }

    private static void logChunked(String label, String text) {
        if (text == null) {
            Log.i(TAG, label + " <null>");
            return;
        }
        final int chunk = 3000;
        int total = (text.length() + chunk - 1) / chunk;
        if (total == 0) {
            Log.i(TAG, label + " <empty>");
            return;
        }
        for (int i = 0; i < total; i++) {
            int start = i * chunk;
            int end = Math.min(start + chunk, text.length());
            Log.i(TAG, label + " " + (i + 1) + "/" + total + " " + text.substring(start, end));
        }
    }

    /**
     * Read a (repeatable) request body without a compile-time okio dependency.
     * Fable-remoting bodies are small JSON strings, so this is cheap and safe.
     */
    private static String readRequestBody(Request request) {
        try {
            Object rb = request.body();
            if (rb == null) return null;
            Class<?> bufferCls = Class.forName("okio.Buffer");
            Class<?> sinkCls = Class.forName("okio.BufferedSink");
            Object buffer = bufferCls.getConstructor().newInstance();
            Method writeTo = rb.getClass().getMethod("writeTo", sinkCls);
            writeTo.invoke(rb, buffer);
            Method readUtf8 = bufferCls.getMethod("readUtf8");
            return (String) readUtf8.invoke(buffer);
        } catch (Throwable t) {
            return "<unreadable: " + t.getClass().getSimpleName() + ">";
        }
    }

    private static String readTextFile(File f) {
        if (f == null || !f.isFile()) return null;
        try (FileInputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return out.toString("UTF-8");
        } catch (Throwable t) {
            Log.w(TAG, "readTextFile failed " + f + ": " + t.getMessage());
            return null;
        }
    }

    /** RevenueCat /subscribers response — schema is known, spoof it wholesale. */
    private static String rewriteRevenueCat(String body) {
        String trimmed = body.trim();
        if (!trimmed.startsWith("{")) return null;
        try {
            JSONObject root = new JSONObject(body);
            if (!root.has("subscriber") && !root.has("entitlements")) {
                return null;
            }
            spoofCustomerInfoJson(root);
            return root.toString();
        } catch (Throwable t) {
            Log.w(TAG, "rewriteRevenueCat failed: " + t.getMessage());
            return null;
        }
    }

    /**
     * coach.myoadapt session payload — schema is *not* fully known and the same
     * response carries unrelated app state, so only subscription-scoped values are
     * edited, and only in place.
     */
    private static String rewriteBackend(String body) {
        String trimmed = body.trim();
        try {
            if (trimmed.startsWith("{")) {
                JSONObject obj = new JSONObject(body);
                return unlockObject(obj, false) ? obj.toString() : null;
            }
            if (trimmed.startsWith("[")) {
                JSONArray arr = new JSONArray(body);
                return unlockArray(arr, false) ? arr.toString() : null;
            }
        } catch (Throwable t) {
            Log.w(TAG, "rewriteBackend failed: " + t.getMessage());
        }
        return null;
    }

    /**
     * @param inSubScope true once we are inside a subscription object, where every
     *     status/expiry field belongs to the subscription and is safe to edit.
     *     Outside of it only self-describing keys (isSubscribed, hasAccess, …) are
     *     touched, so a program's `status` or a workout's `endDate` is left alone.
     */
    private static boolean unlockObject(JSONObject obj, boolean inSubScope) {
        if (obj == null) return false;
        boolean touched = false;
        ArrayList<String> keys = new ArrayList<>();
        Iterator<String> it = obj.keys();
        while (it.hasNext()) keys.add(it.next());

        for (String key : keys) {
            Object val = obj.opt(key);
            boolean childScope = inSubScope || isSubscriptionContainerKey(key);
            if (val instanceof JSONObject) {
                touched |= unlockObject((JSONObject) val, childScope);
            } else if (val instanceof JSONArray) {
                touched |= unlockArray((JSONArray) val, childScope);
            } else if (inSubScope || isSubscriptionFieldKey(key)) {
                touched |= unlockValue(obj, key, val);
            }
        }
        return touched;
    }

    private static boolean unlockArray(JSONArray arr, boolean inSubScope) {
        if (arr == null) return false;
        boolean touched = false;
        for (int i = 0; i < arr.length(); i++) {
            Object val = arr.opt(i);
            if (val instanceof JSONObject) {
                touched |= unlockObject((JSONObject) val, inSubScope);
            } else if (val instanceof JSONArray) {
                touched |= unlockArray((JSONArray) val, inSubScope);
            } else if (inSubScope && val instanceof String && isInactiveStatus((String) val)) {
                // Fable DU serialized as ["Expired"], inside a subscription field.
                try {
                    arr.put(i, "Active");
                    touched = true;
                } catch (Throwable ignored) {
                }
            }
        }
        return touched;
    }

    /** Rewrite one scalar. Never adds a key, never changes a value's type. */
    private static boolean unlockValue(JSONObject obj, String key, Object val) {
        String k = key.toLowerCase(Locale.ROOT);
        try {
            if (val instanceof String) {
                String s = (String) val;
                boolean statusKey =
                        k.equals("case") || k.equals("state") || k.contains("status");
                if (statusKey && isInactiveStatus(s)) {
                    obj.put(key, Character.isUpperCase(s.charAt(0)) ? "Active" : "active");
                    return true;
                }
                if (isExpiryKey(k) && isDateBefore2030(s)) {
                    obj.put(key, EXPIRE);
                    return true;
                }
                return false;
            }
            if (val instanceof Boolean) {
                boolean b = (Boolean) val;
                if (b && (k.contains("expired") || k.contains("cancel") || k.contains("lapsed"))) {
                    obj.put(key, false);
                    return true;
                }
                if (!b
                        && (k.contains("active")
                                || k.contains("access")
                                || k.contains("subscribed")
                                || k.contains("premium")
                                || k.contains("entitled")
                                || k.contains("paid")
                                || k.contains("pro"))) {
                    obj.put(key, true);
                    return true;
                }
            }
            // Numbers are left alone on purpose: the enum ordering is unknown, and
            // guessing at it corrupts unrelated records.
        } catch (Throwable ignored) {
        }
        return false;
    }

    /** Keys whose value is the subscription object itself. */
    private static boolean isSubscriptionContainerKey(String key) {
        String k = key.toLowerCase(Locale.ROOT);
        return k.equals("sub")
                || k.equals("subs")
                || k.startsWith("subscription")
                || k.equals("membership")
                || k.equals("entitlement")
                || k.equals("entitlements");
    }

    /**
     * Keys that describe subscription state by name alone, so they can be edited
     * wherever they appear.
     */
    private static boolean isSubscriptionFieldKey(String key) {
        String k = key.toLowerCase(Locale.ROOT);
        return k.contains("subscri")
                || k.contains("entitlement")
                || k.contains("premium")
                || k.equals("isexpired")
                || k.equals("trialexpired")
                || k.equals("istrialexpired")
                || k.equals("hasaccess")
                || k.equals("hasfullaccess")
                || k.equals("haspaidaccess")
                || k.equals("ispaid")
                || k.equals("ispro");
    }

    private static boolean isExpiryKey(String lowerKey) {
        return lowerKey.contains("expir")
                || lowerKey.contains("validuntil")
                || lowerKey.contains("periodend")
                || lowerKey.contains("renewal")
                || lowerKey.contains("renewsat")
                || lowerKey.equals("enddate")
                || lowerKey.equals("endson");
    }

    private static boolean isInactiveStatus(String value) {
        if (value == null) return false;
        String v = value.toLowerCase(Locale.ROOT);
        for (String s : INACTIVE_STATUSES) {
            if (v.equals(s)) return true;
        }
        return false;
    }

    /** ISO-ish date string that has already passed (or is about to). */
    private static boolean isDateBefore2030(String s) {
        if (s == null || s.length() < 10) return false;
        if (!s.startsWith("20") || s.charAt(4) != '-') return false;
        return s.compareTo("2030") < 0;
    }

    /**
     * Called from CustomerInfoFactory.buildCustomerInfo and for RevenueCat network
     * responses. Schema is RevenueCat's, so it can be rewritten wholesale.
     */
    public static void spoofCustomerInfoJson(JSONObject body) {
        if (body == null) return;
        try {
            JSONObject subscriber = body.optJSONObject("subscriber");
            if (subscriber == null) {
                if (body.has("entitlements") || body.has("subscriptions")) {
                    subscriber = body;
                } else {
                    return;
                }
            }

            JSONObject entEntry = new JSONObject();
            entEntry.put("expires_date", EXPIRE);
            entEntry.put("purchase_date", PURCHASE);
            entEntry.put("product_identifier", PRODUCT);
            entEntry.put("product_plan_identifier", PLAN);
            entEntry.put("grace_period_expires_date", JSONObject.NULL);

            JSONObject entitlements = new JSONObject();
            entitlements.put("core-access", entEntry);
            entitlements.put("duo-access", entEntry);
            subscriber.put("entitlements", entitlements);

            JSONObject subEntry = new JSONObject();
            subEntry.put("expires_date", EXPIRE);
            subEntry.put("purchase_date", PURCHASE);
            subEntry.put("original_purchase_date", PURCHASE);
            subEntry.put("period_type", "normal");
            subEntry.put("store", "play_store");
            subEntry.put("is_sandbox", false);
            subEntry.put("unsubscribe_detected_at", JSONObject.NULL);
            subEntry.put("billing_issues_detected_at", JSONObject.NULL);
            subEntry.put("grace_period_expires_date", JSONObject.NULL);
            subEntry.put("ownership_type", "PURCHASED");
            subEntry.put("product_plan_identifier", PLAN);
            subEntry.put("auto_resume_date", JSONObject.NULL);
            subEntry.put("refunded_at", JSONObject.NULL);

            JSONObject subscriptions = new JSONObject();
            subscriptions.put(PRODUCT, subEntry);
            subscriptions.put("main_sub", subEntry);
            subscriptions.put("solo_sub_annual", subEntry);
            subscriptions.put("solo_sub_monthly", subEntry);
            subscriber.put("subscriptions", subscriptions);

            if (!subscriber.has("non_subscriptions")) {
                subscriber.put("non_subscriptions", new JSONObject());
            }
        } catch (Throwable t) {
            Log.w(TAG, "spoofCustomerInfoJson failed: " + t.getMessage());
        }
    }
}
