package com.germanlizondo.cryptografiachat;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;

import com.github.nkzawa.emitter.Emitter;
import com.github.nkzawa.socketio.client.IO;
import com.github.nkzawa.socketio.client.Socket;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ChatActivity extends AppCompatActivity {

   private EditText inputtext;
   private ListView listMessages;
   private Socket socket;
   private Message message;
   private JSONObject jsonMessage;
   private ArrayList<Message> arrayMensajes;
   private String username;
   private SecretKey sKey;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat);

        this.sKey = this.keygenKeyGeneration("hola",256);
        this.username = getIntent().getStringExtra("username");

        this.arrayMensajes = new ArrayList<Message>();
        this.inputtext = (EditText) findViewById(R.id.messageData);
        this.listMessages = (ListView) findViewById(R.id.listMessages);
        this.conncetToSocker();
        this.receiveMessage();

    }




    public void setAdapterListMessages(){
        this.listMessages.setAdapter(new ArrayAdapter<Message>(this, android.R.layout.simple_list_item_1, this.arrayMensajes));
    }


    public void conncetToSocker(){
        try {
            socket = IO.socket("http://192.168.1.76:3000");
            socket.connect();
        } catch (URISyntaxException e) {
            Toast toast = Toast.makeText(getApplicationContext(), "No hay connexion", Toast.LENGTH_SHORT);
            toast.show();
        }
    }

    public void sendMessage(View view) {
        this.message = new Message( this.username,this.inputtext.getText().toString());

        /*JSON INIT*/
        try {

            byte[] encryptedMessage = this.encryptData(this.sKey,this.message.getMessage().getBytes("UTF-8"));

            this.jsonMessage = new JSONObject();
            this.jsonMessage.put("nickname",this.message.getNickname());
            this.jsonMessage.put("message",encryptedMessage.toString());
        }catch (JSONException e){
            e.printStackTrace();
        }catch (UnsupportedEncodingException ex){
            ex.printStackTrace();
        }


    this.socket.emit("new message",this.jsonMessage);
    this.inputtext.setText("");

    }

    public void receiveMessage(){

        this.socket.on("new message", new Emitter.Listener() {
            @Override
            public void call(final Object... args) {

                ChatActivity.this.runOnUiThread(new Runnable() {
                   @Override
                   public void run() {
                       JSONObject data = (JSONObject) args[0];
                       try {
                           addMessage(data.getString("nickname"),data.getString("message"));
                       } catch (JSONException e) {
                           return;
                       }

                   }
               });
            }
        });
    }

    public void addMessage(String nickname,String message){
try{

   byte[] desencryptedMessage = this.decryptData(this.sKey,message.getBytes("UTF-8"));
  //  this.arrayMensajes.add(new Message(nickname,desencryptedMessage.toString()));
 //   this.setAdapterListMessages();

    Toast toast = Toast.makeText(getApplicationContext(), message, Toast.LENGTH_SHORT);
    toast.show();
}catch (UnsupportedEncodingException ex){
    ex.printStackTrace();
}

    }


    public SecretKey keygenKeyGeneration(String text,int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash,keySize/8);
                sKey = new SecretKeySpec(key,"AES");
            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }catch (UnsupportedEncodingException ex){
                ex.printStackTrace();
            }
        }
        return sKey;
    }


    public byte[] encryptData(SecretKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }

    public byte[] decryptData(SecretKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }
    @Override
    public void onDestroy() {
        super.onDestroy();

        socket.disconnect();

    }

}
