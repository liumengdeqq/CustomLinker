package com.example.memloadertest;

import android.graphics.Color;
import android.os.Build;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

//      CustomTextView customTextView=(CustomTextView)findViewById(R.id.ringView);
//      List<Integer> colors=new ArrayList();
//      colors.add(Color.RED);
//      colors.add(Color.BLUE);
//      List<Float> rate=new ArrayList();
//      rate.add(50.0f);
//      rate.add(50.0f);
//      customTextView.setShow(colors,rate,true,true);
////         Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText(getString());

    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String getString();
}
