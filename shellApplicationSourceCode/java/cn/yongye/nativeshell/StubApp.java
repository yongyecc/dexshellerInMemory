package cn.yongye.nativeshell;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import android.util.Log;
import android.app.Application;
import android.content.Context;
import cn.yongye.nativeshell.inmemoryloaddex.MyDexClassLoader;


public class StubApp extends Application {

    public static final String TAG = "yongye";
    
    static {
        System.loadLibrary("yongyejiagu");
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        loadDEX();

    }

    public native void loadDEX();
}
