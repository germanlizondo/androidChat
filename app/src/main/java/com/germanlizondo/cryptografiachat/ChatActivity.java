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

import org.java_websocket.util.Base64;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
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
   private KeyPairGenerator keyGen;
   private KeyPair parellaClaus;
   private Cipher xifrarRSA;
   private PublicKey publickeyExternal;
   private SecretKey secretKeyAes;
   private static final String KEYAES = "hola";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat);

        this.username = getIntent().getStringExtra("username");

        this.arrayMensajes = new ArrayList<Message>();
        this.inputtext = (EditText) findViewById(R.id.messageData);
        this.listMessages = (ListView) findViewById(R.id.listMessages);

        this.secretKeyAes = this.scretKeyAES(KEYAES,256);


        try {
            this.keyGen = KeyPairGenerator.getInstance("RSA");
            this.keyGen.initialize(1024);
            this.parellaClaus = keyGen.generateKeyPair();
            this.xifrarRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        }catch (NoSuchAlgorithmException | NoSuchPaddingException e){
             e.fillInStackTrace();
        }

        this.conncetToSocker();
        this.receiveMessage();
        this.recivedPubliKey();




    }




    public void setAdapterListMessages(){
        this.listMessages.setAdapter(new ArrayAdapter<Message>(this, android.R.layout.simple_list_item_1, this.arrayMensajes));
    }


    public void conncetToSocker(){
        try {
            socket = IO.socket("http://172.20.22.3:3000");
            socket.connect();




            byte[] pKbytes = android.util.Base64.encode(this.parellaClaus.getPublic().getEncoded(),0);

          JSONObject  json = new JSONObject();
            json.put("user",this.username);
            json.put("PublicKey",new String(pKbytes));

            socket.emit("new user",json);
        } catch (URISyntaxException | JSONException e) {
            Toast toast = Toast.makeText(getApplicationContext(), "No hay connexion", Toast.LENGTH_SHORT);
            toast.show();
        }
    }

    public void sendMessage(View view) {
        this.message = new Message( this.username,this.inputtext.getText().toString());

        byte[] encryptedDataAes;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.secretKeyAes);
            encryptedDataAes = cipher.doFinal(message.getNickname().getBytes());
        } catch (Exception ex) {
            encryptedDataAes = null;
            System.err.println("Error xifrant les dades: " + ex);
        }

        /*JSON INIT*/
        try {
            byte[] missatge = this.message.getMessage().getBytes();

            // Inicialització del xifrador: xifrem amb la clau pública
            xifrarRSA.init(Cipher.ENCRYPT_MODE, this.publickeyExternal);

            // Xifrat del missatge
            byte[] missatgeXifrat = xifrarRSA.doFinal(missatge);

            byte[] pKbytes = android.util.Base64.encode(this.parellaClaus.getPublic().getEncoded(),0);


            this.jsonMessage = new JSONObject();
            this.jsonMessage.put("nickname",encryptedDataAes);
            this.jsonMessage.put("message",new String(missatgeXifrat));
            this.jsonMessage.put("signatura",new String(this.signData(missatge,this.parellaClaus.getPrivate())));
            this.jsonMessage.put("PublicKey",new String(pKbytes));



        }catch (JSONException e){
            e.printStackTrace();
        }catch (Exception ex){
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
                           if(validateSignature(decryptData(data.getString("message")) ,
                                   data.getString("signatura").getBytes(),createPublicKey(data.getString("PublicKey")))){

                               addMessage(data.getString("nickname"),data.getString("message"));

                           }else{
                               Toast toast = Toast.makeText(getApplicationContext(), "Error en la signatura", Toast.LENGTH_SHORT);
                               toast.show();
                           }
                       } catch (JSONException e) {
                           return;
                       }

                   }
               });
            }
        });
    }

    public void recivedPubliKey(){

        this.socket.on("new user", new Emitter.Listener() {
            @Override
            public void call(final Object... args) {

                ChatActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            JSONObject data = (JSONObject) args[0];

                            addPubliKey(data.getString("PublicKey"));

                        } catch (JSONException e) {
                            return;
                        }

                    }
                });
            }
        });
    }

    public void addPubliKey(String key){

        KeyFactory kf;

        try{

            byte[] pubKey = Base64.decode(key.getBytes());
            X509EncodedKeySpec ks = new X509EncodedKeySpec(pubKey);
            kf = KeyFactory.getInstance("RSA");
            this.publickeyExternal = kf.generatePublic(ks);
            Toast toast = Toast.makeText(getApplicationContext(), "Connected: ", Toast.LENGTH_SHORT);
            toast.show();

        }catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException ex){
            ex.fillInStackTrace();
            Toast toast = Toast.makeText(getApplicationContext(), "Error: ", Toast.LENGTH_SHORT);
            toast.show();

            ex.fillInStackTrace();
        }




    }

    public PublicKey createPublicKey(String key){

        KeyFactory kf;
        try{

            byte[] pubKey = Base64.decode(key.getBytes());
            X509EncodedKeySpec ks = new X509EncodedKeySpec(pubKey);
            kf = KeyFactory.getInstance("RSA");
           PublicKey publicKey = kf.generatePublic(ks);

           return publicKey;

        }catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException ex){
            ex.fillInStackTrace();
            Toast toast = Toast.makeText(getApplicationContext(), "Error: ", Toast.LENGTH_SHORT);
            toast.show();

            ex.fillInStackTrace();
            return null;
        }

    }


    public void addMessage(String nickname,String message){
try{

    this.arrayMensajes.add(new Message(nickname,this.decryptData(message).toString()+": HOLA"));
    this.setAdapterListMessages();

    Toast toast = Toast.makeText(getApplicationContext(), message, Toast.LENGTH_SHORT);
    toast.show();
}catch (Exception ex){
    ex.printStackTrace();
}

    }

    public byte[] decryptData(String message){
        try{

            this.xifrarRSA.init(Cipher.DECRYPT_MODE, this.parellaClaus.getPrivate());
            byte[] missatgeDes= this.xifrarRSA.doFinal(message.getBytes());
            Toast toast = Toast.makeText(getApplicationContext(), missatgeDes.toString(), Toast.LENGTH_SHORT);
            toast.show();
            return missatgeDes;
        }catch (Exception ex){
            ex.printStackTrace();

            return null;
        }

    }

    public byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    public boolean validateSignature(byte[] data, byte[] signature, PublicKey pub)
    {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }



    public SecretKey scretKeyAES(String text,int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                byte[] data = text.getBytes();
                MessageDigest md = MessageDigest.getInstance("SHA − 256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize/8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }





    @Override
    public void onDestroy() {
        super.onDestroy();

        socket.disconnect();

    }

}
