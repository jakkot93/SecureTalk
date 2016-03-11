package com.jakkot93.securetalk;

import android.app.Activity;
import android.content.Context;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioTrack;
import android.media.MediaRecorder;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
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

public class CallServer extends Activity {

    private static final String TAG = "JK93";

    //Functions
    Functions functions = null;

    //AUDIO
    AudioRecord recorder;
    Boolean recording, isSpeakerPhoneOn;
    int oldAudioMode, oldRingerMode;
    AudioManager audioManager = null;
    int SAMPLERATE = 8000;

    //CHAT
    static final int SocketServerPORT = 8080;
    ServerSocket serverSocket;
    ConnectThread connectThread = null;
    List<ChatClient> userList;
    int Counter = 0;
    boolean goOut = false;

    //Msg
    byte[] msgByte = null;
    String newMsg = null;

    //Layout
    TextView infoIp, chatMsg, channel, wait;
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
        setContentView(R.layout.activity_call_server);
        infoIp = (TextView) findViewById(R.id.InfoIp);
        wait = (TextView) findViewById(R.id.wait);
        chatMsg = (TextView) findViewById(R.id.ChatMsgServer);
        channel = (TextView) findViewById(R.id.channelServer);
        send = (Button) findViewById(R.id.send);
        spinner = (ProgressBar)findViewById(R.id.progressBar);

        spinner.setVisibility(View.VISIBLE);

        userList = new ArrayList<ChatClient>();

        audioManager = (AudioManager)getSystemService(Context.AUDIO_SERVICE);
        oldAudioMode = audioManager.getMode();
        oldRingerMode = audioManager.getRingerMode();
        isSpeakerPhoneOn = audioManager.isSpeakerphoneOn();

        functions = new Functions();

        infoIp.setText(functions.getIpAddress());

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

        send.setEnabled(false);

        ChatServerThread chatServerThread = new ChatServerThread();
        chatServerThread.start();
    }

    public void Disconnect (View view) {
        if (connectThread == null) {
            return;
        }
        goOut = true;
        Toast.makeText(CallServer.this, "Disconnect", Toast.LENGTH_LONG).show();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        audioManager.setSpeakerphoneOn(isSpeakerPhoneOn);
        audioManager.setMode(oldAudioMode);
        audioManager.setRingerMode(oldRingerMode);

        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void SendMsgButton(View view){

        send.setVisibility(view.GONE);

        recorder = new AudioRecord(MediaRecorder.AudioSource.MIC, SAMPLERATE,
                AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, 1024);
        recorder.startRecording();

        Thread recordThread = new Thread(new Runnable() {

            @Override
            public void run() {
                recording = true;
                recordAndWriteAudioData();
            }

        });
        recordThread.start();
    }

    private void recordAndWriteAudioData() {

        byte audioData[] = new byte[1024];

        while (recording) {
            recorder.read(audioData, 0, 1024);
            msgByte = functions.EncryptionAES(audioData, SecretKeyAES);
        }
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
                    CallServer.this.runOnUiThread(new Runnable() {
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

        ConnectThread(ChatClient client, Socket socket) {
            connectClient = client;
            this.socket = socket;
            client.socket = socket;
            client.chatThread = this;
        }

        String digest = null;
        byte[] encoded = null;
        byte[] sign = null;
        boolean IsVerify = false;

        @Override
        public void run() {
            DataInputStream dataInputStream = null;
            DataOutputStream dataOutputStream = null;

            AudioTrack at = new AudioTrack(AudioManager.STREAM_MUSIC, SAMPLERATE, AudioFormat.CHANNEL_OUT_MONO,
                    AudioFormat.ENCODING_PCM_16BIT, 1024, AudioTrack.MODE_STREAM);
            at.play();
            audioManager = (AudioManager) getSystemService(Context.AUDIO_SERVICE);
            audioManager.setSpeakerphoneOn(false);
            audioManager.setMode(AudioManager.MODE_IN_COMMUNICATION);

            try {
                dataInputStream = new DataInputStream(socket.getInputStream());
                dataOutputStream = new DataOutputStream(socket.getOutputStream());

                String n = dataInputStream.readUTF();

                connectClient.name = n;

                while (!goOut) {
                    if (dataInputStream.available() > 0) {

                        byte[] inputData = null;
                        try {
                            int length = dataInputStream.readInt();                    // read length of incoming message
                            if (length > 0) {
                                inputData = new byte[length];
                                dataInputStream.readFully(inputData, 0, inputData.length); // read the message
                            }
                        } catch (Exception e) {
                            Log.e(TAG, "blad odebrania");
                        }

                        switch (Counter) {

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
                                CallServer.this.runOnUiThread(new Runnable() {
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
                                byte[] audioData = functions.DecryptionAES(inputData, SecretKeyAES);
                                at.write(audioData, 0, 1024);
                                break;
                        }
                    }

                    if (msgByte != null) {
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
                CallServer.this.runOnUiThread(new Runnable() {

                    @Override
                    public void run() {
                        Toast.makeText(CallServer.this,
                                connectClient.name + " removed.", Toast.LENGTH_LONG).show();

                        newMsg += "-- " + connectClient.name + " leaved\n";
                        CallServer.this.runOnUiThread(new Runnable() {

                            @Override
                            public void run() {
                                chatMsg.setText(newMsg);
                            }
                        });
                    }
                });
            }

            at.stop();
            at.release();

        }
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