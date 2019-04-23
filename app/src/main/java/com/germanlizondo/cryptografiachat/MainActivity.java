package com.germanlizondo.cryptografiachat;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    private EditText nicknameInput;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        this.nicknameInput = (EditText) findViewById(R.id.nicknameInput);
    }

    public void iniciaChat(View view) {
        if(this.nicknameInput.getText().equals("")){
            Toast toast = Toast.makeText(getApplicationContext(), "Write a nickname!", Toast.LENGTH_SHORT);
            toast.show();

        }else{

            Intent intent = new Intent(this,ChatActivity.class);
            intent.putExtra("username",this.nicknameInput.getText().toString());
            startActivity(intent);
        }

    }
}
