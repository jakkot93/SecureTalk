package com.jakkot93.securetalk;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class ChatClient extends Activity {

    private static final String TAG = "JK93";
    public static String seed = "I AM UNBREAKABLE";

    //Functions
    Functions functions = null;

    //Connection
    static final int SERVER_PORT = 8080;
    String SERVER_IP;
    ChatClientThread chatClientThread = null;
    int Counter = 0;

    //Msg
    byte[] msgByte = null;
    String newMsg = null;
    String TabMsg [];

    //Layout
    TextView chatMsg, channel;
    EditText msg;
    Button authorization, send;
    ProgressBar spinner;

    //RSA
    PrivateKey privateKey = null;
    PublicKey publicKey = null;
    PublicKey ServerPublicKey = null;

    //AES
    SecretKey SecretKeyAES = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat_client);

        spinner = (ProgressBar)findViewById(R.id.progressBar);
        spinner.setVisibility(View.GONE);

        SERVER_IP  = getIntent().getStringExtra(MainActivity.AddressIP);

        msg = (EditText) findViewById(R.id.editTextClient);
        chatMsg = (TextView) findViewById(R.id.ChatMsgClient);
        channel = (TextView) findViewById(R.id.channelClient);
        authorization = (Button) findViewById(R.id.authorization);
        send = (Button) findViewById(R.id.send);

        TabMsg = new String[5];
        TabMsg[0] = " ";
        TabMsg[1] = " ";
        TabMsg[2] = " ";
        TabMsg[3] = " ";
        TabMsg[4] = " ";

        functions = new Functions();

        //CREATE RSA
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            String alias = "SecureTalk";

            KeyStore.PrivateKeyEntry privateKeyEntry2 = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            privateKey = privateKeyEntry2.getPrivateKey();
            publicKey = privateKeyEntry2.getCertificate().getPublicKey();

        } catch (Exception e) {
            e.printStackTrace();
        }

        //CREATE AES
        SecretKeyAES = functions.GenerateKeyAES(seed);

        chatClientThread = new ChatClientThread("Client", SERVER_IP, SERVER_PORT);
        chatClientThread.start();
    }



    public void Disconnect (View view) {
        if (chatClientThread == null) {
            return;
        }
        chatClientThread.disconnect();
        Toast.makeText(ChatClient.this, "Disconnect", Toast.LENGTH_LONG).show();
    }

    public void Authorization (View view){
        msgByte = publicKey.getEncoded();
        authorization.setVisibility(view.GONE);
        send.setVisibility(view.VISIBLE);
        spinner.setVisibility(View.VISIBLE);
    }

    public void SendMsgButton(View view) {
        if (msg.getText().toString().equals("")) {
            Toast.makeText(ChatClient.this, "Enter Msg", Toast.LENGTH_LONG).show();
            return;
        }
        if (chatClientThread == null) {
            return;
        }
        String ed = msg.getText().toString();

        TabMsg[4] = TabMsg[3];
        TabMsg[3] = TabMsg[2];
        TabMsg[2] = TabMsg[1];
        TabMsg[1] = TabMsg[0];
        TabMsg[0] = "You: " + ed;
        chatMsg.setText(TabMsg[0] + "\n" + TabMsg[1] + "\n" + TabMsg[2] + "\n" + TabMsg[3] + "\n" + TabMsg[4] + "\n");

        msgByte = functions.EncryptionAES(ed.getBytes(), SecretKeyAES);
    }

    private class ChatClientThread extends Thread {

        String name;
        String dstAddress;
        int dstPort;
        boolean goOut = false;

        ChatClientThread(String name, String address, int port) {
            this.name = name;
            dstAddress = address;
            dstPort = port;
        }

        @Override
        public void run() {

            Socket socket = null;
            DataOutputStream dataOutputStream = null;
            DataInputStream dataInputStream = null;

            try {
                socket = new Socket(dstAddress, dstPort);
                dataOutputStream = new DataOutputStream(socket.getOutputStream());
                dataInputStream = new DataInputStream(socket.getInputStream());
                dataOutputStream.writeUTF(name);
                dataOutputStream.flush();

                byte[] encoded = null;
                byte[] sign = null;
                boolean IsVerify = false;

                while (!goOut) {
                    if (dataInputStream.available() > 0) {

                        byte[] inputData = null;
                        try {
                            int length = dataInputStream.readInt(); // read length of incoming message
                            if (length > 0) {
                                inputData = new byte[length];
                                dataInputStream.readFully(inputData, 0, inputData.length);  // read the message
                            }
                        }
                        catch (Exception e) {
                            Log.e(TAG, "Blad odebrania");
                        }

                        switch (Counter){

                            case 0:
                                ServerPublicKey = functions.DownloadedPublicKey(inputData);
                                Log.e(TAG, "Pobrano klucz");
                                encoded = functions.EncryptionRSAAndroidKS(SecretKeyAES.getEncoded(), ServerPublicKey);
                                msgByte = functions.Signed(encoded, privateKey);
                                Counter++;
                                break;

                            case 1:
                                msgByte = encoded;
                                Counter++;
                                break;

                            case 2:
                                sign = inputData;
                                msgByte = "Empty MSG".getBytes();
                                Counter++;
                                break;

                            case 3:
                                String success;
                                IsVerify = functions.Verify(inputData, ServerPublicKey, sign);
                                if(IsVerify == true){
                                    byte[] decoded = functions.DecryptionRSAAndroidKS(inputData, privateKey);
                                    String hash1 = new String(decoded).trim();
                                    String hash2 = functions.DigestFromMsg(SecretKeyAES.getEncoded());
                                    Log.i(TAG, "Hash1 " + hash1);
                                    Log.i(TAG, "Hash2 " + hash2);

                                    if(hash1.equals(hash2))
                                        success = "Channel Protected";
                                    else
                                        success = "Authorization Failed";

                                    final String suc = success;
                                    ChatClient.this.runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            channel.setText(suc);
                                            send.setEnabled(true);
                                            spinner.setVisibility(View.GONE);
                                        }
                                    });
                                }
                                else
                                    success = "Authorization Failed";
                                msgByte = functions.EncryptionRSAAndroidKS(success.getBytes(), ServerPublicKey);
                                Counter++;
                                break;

                            case 4:
                                byte[] msg = functions.DecryptionAES(inputData, SecretKeyAES);
                                newMsg = new String(msg).trim();
                                TabMsg[4] = TabMsg[3];
                                TabMsg[3] = TabMsg[2];
                                TabMsg[2] = TabMsg[1];
                                TabMsg[1] = TabMsg[0];
                                TabMsg[0] = "Sender: " + newMsg;
                                ChatClient.this.runOnUiThread(new Runnable() {

                                    @Override
                                    public void run() {
                                        chatMsg.setText(TabMsg[0]+"\n"+TabMsg[1]+"\n"+TabMsg[2]+"\n"+TabMsg[3]+"\n"+TabMsg[4]+"\n");
                                    }
                                });
                                break;
                        }
                    }
                    if(msgByte != null){
                        dataOutputStream.writeInt(msgByte.length); // write length of the message
                        dataOutputStream.write(msgByte);           // write the message
                        msgByte = null;
                    }
                }

            } catch (UnknownHostException e) {
                e.printStackTrace();
                final String eString = e.toString();
                ChatClient.this.runOnUiThread(new Runnable() {

                    @Override
                    public void run() {
                        Toast.makeText(ChatClient.this, eString, Toast.LENGTH_LONG).show();
                    }

                });
            } catch (IOException e) {
                e.printStackTrace();
                final String eString = e.toString();
                ChatClient.this.runOnUiThread(new Runnable() {

                    @Override
                    public void run() {
                        Toast.makeText(ChatClient.this, eString, Toast.LENGTH_LONG).show();
                    }

                });
            } finally {
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                if (dataOutputStream != null) {
                    try {
                        dataOutputStream.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                if (dataInputStream != null) {
                    try {
                        dataInputStream.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        private void disconnect(){
            goOut = true;
        }
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event)  {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.ECLAIR
                && (keyCode == KeyEvent.KEYCODE_BACK)
                && event.getRepeatCount() == 0)
        {
            onBackPressed();
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override
    public void onBackPressed() {
        // Do nothing
    }
}