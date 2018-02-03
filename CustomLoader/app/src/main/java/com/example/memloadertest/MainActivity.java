package com.example.memloadertest;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

//    @Override
//    protected void onCreate(Bundle savedInstanceState) {
//        super.onCreate(savedInstanceState);
//        setContentView(R.layout.activity_main);
//    }
    private TextView tv;

    static{
        System.loadLibrary("Mini_elf_loader");
    }
//    static {
//        System.loadLibrary("foo");
//}

    public native String getString();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        tv = (TextView)findViewById(R.id.main_tv);
        tv.setText(getString());
    }
}
