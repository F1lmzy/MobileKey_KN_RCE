// KN extractor for com.trevo.nus (SaltOS JustIn Mobile SDK)
// Attach: frida -H 127.0.0.1:27042 -n Gadget -l kn.js
// Then trigger one lock/unlock in the app.

function hex(b) {
    var s = "";
    for (var i = 0; i < b.length; i++) s += ("0" + (b[i] & 0xff).toString(16)).slice(-2);
    return s;
}

Java.perform(function () {
    console.log("[*] hooks installing...");

    // Net 1: full TLV digital-key blob as delivered from Flutter/cloud.
    // KN is the value under BER-TLV tag 01 in this hex string.
    try {
        var Z = Java.use("com.saltosystems.justinmobile.obscured.z"); // DigitalKeyBase
        Z.$init.overload("java.lang.String").implementation = function (h) {
            console.log("\n========== [KEY BLOB] ==========");
            console.log(h);
            console.log("================================\n");
            return this.$init(h);
        };
    } catch (e) { console.log("[!] z hook failed: " + e); }

    // Net 2: KN exactly at authentication time
    try {
        var Q1 = Java.use("com.saltosystems.justinmobile.obscured.q1");
        Q1.m976a.implementation = function () {
            var kn = this.m976a();
            console.log("\n[KN] " + hex(kn) + "\n");
            return kn;
        };
    } catch (e) { console.log("[!] q1 hook failed: " + e); }

    // Net 3: every SaltoEncryptor AES-CBC operation (key, IV, plaintext, ciphertext)
    try {
        var M2C = Java.use("com.saltosystems.justinmobile.obscured.m2$c");
        var CBC = "com.saltosystems.justinmobile.obscured.m2$b";
        var PAD = "com.saltosystems.justinmobile.obscured.m2$d";

        M2C.b.overload("[B", "[B", "[B", CBC, PAD).implementation = function (inp, key, iv, mode, pad) {
            console.log("[AES-ENC] k=" + hex(key) + " iv=" + hex(iv));
            console.log("          pt=" + hex(inp));
            var out = this.b(inp, key, iv, mode, pad);
            console.log("          ct=" + hex(out));
            return out;
        };

        M2C.a.overload("[B", "[B", "[B", CBC, PAD).implementation = function (inp, key, iv, mode, pad) {
            var out = this.a(inp, key, iv, mode, pad);
            console.log("[AES-DEC] k=" + hex(key) + " iv=" + hex(iv));
            console.log("          ct=" + hex(inp));
            console.log("          pt=" + hex(out));
            return out;
        };
    } catch (e) { console.log("[!] m2 hook failed: " + e); }

    console.log("[*] hooks installed. Now trigger a lock/unlock in the app.");
});
