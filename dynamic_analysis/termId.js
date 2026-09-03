function logging(state) {
    console.log(JSON.stringify(state, null, 2));
}

function currentThreadId(Thread) {
    return Thread.currentThread().getId().toString();
}

Java.perform(function () {
    const Build = Java.use("android.os.Build"); // Android device information, used as a substring for termID
    const Thread = Java.use("java.lang.Thread"); // Using ThreadID to track termID building methods (it is only assumed that all methods run on the same thread)
    const idBuilder = Java.use("com.tplink.libtapoiotnetwork.utils.m"); // Custom class to build termID
    const SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
    const idStates = new Map();

    // Bypass cached termID, if it exists
    SharedPreferencesImpl.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, defValue) {
        if (key === 'term_uuid_new') { return ''; }
        return this.getString(key, defValue);
    };

    idBuilder.d.overload().implementation = function() {
        // The substring is initialized with a value of "35".
        // It is further built by taking a String value of a system property,
        // Computing it's length and appending the last digit to a substring.
        const output = this.d();

        const threadId = currentThreadId(Thread);

        const state = {
            header: 35
        };

        const keys = [
            "board",
            "brand",
            "cpu_abi",
            "device",
            "display",
            "host",
            "id",
            "manufacturer",
            "model",
            "product",
            "tags",
            "type",
            "user"
        ];

        const values = [
            Build.BOARD.value,
            Build.BRAND.value,
            Build.CPU_ABI.value,
            Build.DEVICE.value,
            Build.DISPLAY.value,
            Build.HOST.value,
            Build.ID.value,
            Build.MANUFACTURER.value,
            Build.MODEL.value,
            Build.PRODUCT.value,
            Build.TAGS.value,
            Build.TYPE.value,
            Build.USER.value
        ];

        for (let i = 0; i < keys.length; i++) {
            state[keys[i]] = {
                name: values[i],
                length: values[i].length,
                lastDigit: `${values[i].length % 10}`
            };
        }

        state.buildInfo = output;

        idStates.set(threadId, state);

        return output;
    }

    idBuilder.a.overload("android.content.Context").implementation = function (context) {
        // Capture Android device ID
        const result = this.a(context);
        const threadId = currentThreadId(Thread);

        let state = idStates.get(threadId);
        if (state !== undefined) {
            state.androidId = result;
            state.fullString = state.buildInfo + state.androidId;
        }

        return result;
    };

    idBuilder.c.overload("android.content.Context").implementation = function (context) {
        // MD5(Android build info + Android device ID).toString().toUpperCase()
        const result = this.c(context);
        const threadId = currentThreadId(Thread);

        let state = idStates.get(threadId);
        if (state !== undefined) {
            state.termID = result;
            logging(state);
            idStates.delete(threadId);
        }

        return result;
    }
});
