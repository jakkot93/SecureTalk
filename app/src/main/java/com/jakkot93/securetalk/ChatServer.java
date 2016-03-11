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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ChatServer extends Activity {

    private static final String TAG = "JK93";

    //Functions
    Functions functions = null;

    //Connection
    static final int SocketServerPORT = 8080;
    ServerSocket serverSocket;
    ConnectThread connectThread = null;
    List<ChatClient> userList;
    int Counter = 0;
    boolean goOut = false;

    //Msg
    byte[] msgByte = null;
    String newMsg = null;
    String TabMsg [];

    //Layout
    TextView infoIp, chatMsg, channel, wait;
    EditText msg;
    Button send;
    ProgressBar spinner;

    //RSA
    PrivateKey privateKey = null;
    PublicKey publicKey = null;
    PublicKey ClientPublicKey = null;

    //AES
    SecretKey SecretKeyAES = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat_server);
        infoIp = (TextView) findViewById(R.id.InfoIp);
        chatMsg = (TextView) findViewById(R.id.ChatMsgServer);
        wait = (TextView) findViewById(R.id.wait);
        channel = (TextView) findViewById(R.id.channelServer);
        msg = (EditText) findViewById(R.id.editTextServer);
        send = (Button) findViewById(R.id.send);
        spinner = (ProgressBar)findViewById(R.id.progressBar);

        spinner.setVisibility(View.VISIBLE);

        TabMsg = new String[5];
        TabMsg[0] = " ";
        TabMsg[1] = " ";
        TabMsg[2] = " ";
        TabMsg[3] = " ";
        TabMsg[4] = " ";

        userList = new ArrayList<ChatClient>();
        send.setEnabled(false);

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

        infoIp.setText(functions.getIpAddress());
        ChatServerThread chatServerThread = new ChatServerThread();
        chatServerThread.start();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void SendMsgButton(View view) {
        if (msg.getText().toString().equals("")) {
            Toast.makeText(ChatServer.this, "Enter Msg", Toast.LENGTH_LONG).show();
            return;
        }
        if (connectThread == null) {
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

    private class ChatServerThread extends Thread {

        @Override
        public void run() {

            Socket socket = null;
            try {
                serverSocket = new ServerSocket(SocketServerPORT);

                while (true) {
                    socket = serverSocket.accept();
                    ChatClient client = new ChatClient();
                    userList.add(client);
                    ChatServer.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            wait.setText("Wait for Authorization...");
                        }
                    });
                    //ConnectThread
                    connectThread = new ConnectThread(client, socket);
                    connectThread.start();
                }

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    private class ConnectThread extends Thread {

        Socket socket;
        ChatClient connectClient;

        ConnectThread(ChatClient client, Socket socket){
            connectClient = client;
            this.socket= socket;
            client.socket = socket;
            client.chatThread = this;
        }

        @Override
        public void run() {
            DataInputStream dataInputStream = null;
            DataOutputStream dataOutputStream = null;

            try {
                dataInputStream = new DataInputStream(socket.getInputStream());
                dataOutputStream = new DataOutputStream(socket.getOutputStream());

                String n = dataInputStream.readUTF();

                connectClient.name = n;

                String digest = null;
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
                            Log.e(TAG, "blad odebrania");
                        }


                        switch (Counter){

                            case 0:
                                //Serwer pobiera PublicKey Klienta, zapisuje do zmiennej
                                ClientPublicKey = functions.DownloadedPublicKey(inputData);
                                //Serwer wysyła do Klienta swój PublicKey
                                msgByte = publicKey.getEncoded();
                                Counter++;
                                break;

                            case 1:
                                //Serwer pobiera podpis od Klienta
                                sign = inputData;
                                //Wysyła pustą wiadomość - synchronizacja
                                msgByte = "Empty MSG".getBytes();
                                Counter++;
                                break;
                            case 2:
                                //Sprawdzenie podpisu
                                IsVerify = functions.Verify(inputData, ClientPublicKey, sign);
                                if(IsVerify == true){
                                    //Jeśli weryfikacja podpisu sie powiodła, to odszyfrowywany jest klucz AES
                                    byte[] decoded = functions.DecryptionRSAAndroidKS(inputData, privateKey);
                                    //Zapis klucza do zmiennej SecretKey
                                    SecretKeyAES = new SecretKeySpec(decoded, "AES");
                                    //Stworzenie skrótu
                                    digest = functions.DigestFromMsg(SecretKeyAES.getEncoded());
                                    //zaszyfrowanie skrótu
                                    encoded = functions.EncryptionRSAAndroidKS(digest.getBytes(), ClientPublicKey);
                                    //Wysłanie podpisu zaszyfrowanego skrótu
                                    msgByte = functions.Signed(encoded, privateKey);
                                    Counter++;
                                }
                                break;

                            case 3:
                                //Wysłąnie zaszyfrowanego skrótu
                                msgByte = encoded;
                                Counter++;
                                break;

                            case 4:
                                //Podbranie statusu, czy kanał jest bezpieczny
                                byte[] msg = functions.DecryptionRSAAndroidKS(inputData, privateKey);
                                newMsg = new String(msg).trim();
                                ChatServer.this.runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        channel.setText(newMsg);
                                        send.setEnabled(true);
                                        spinner.setVisibility(View.GONE);
                                        wait.setVisibility(View.GONE);
                                    }
                                });
                                Counter++;
                                break;

                            case 5:
                                byte[] msg1 = functions.DecryptionAES(inputData, SecretKeyAES);
                                newMsg = new String(msg1).trim();
                                TabMsg[4] = TabMsg[3];
                                TabMsg[3] = TabMsg[2];
                                TabMsg[2] = TabMsg[1];
                                TabMsg[1] = TabMsg[0];
                                TabMsg[0] = "Sender: " + newMsg;
                                ChatServer.this.runOnUiThread(new Runnable() {

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

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (dataInputStream != null) {
                    try {
                        dataInputStream.close();
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

                userList.remove(connectClient);
                ChatServer.this.runOnUiThread(new Runnable() {

                    @Override
                    public void run() {
                        Toast.makeText(ChatServer.this,
                                connectClient.name + " removed.", Toast.LENGTH_LONG).show();
                    }
                });
            }
        }
    }

    public void Disconnect (View view) {
        if (connectThread == null) {
            return;
        }
        goOut = true;
        Toast.makeText(ChatServer.this, "Disconnect", Toast.LENGTH_LONG).show();
    }

    class ChatClient {
        String name;
        Socket socket;
        ConnectThread chatThread;
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