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
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class CallClient extends Activity {

    private static final String TAG = "JK93";
    public static String seed = "I AM UNBREAKABLE";

    //CHAT
    static final int SERVER_PORT = 8080;
    String SERVER_IP;
    ChatClientThread chatClientThread = null;
    int Counter = 0;

    //Functions
    Functions functions = null;

    //Msg
    byte[] msgByte = null;

    //Layout
    TextView chatMsg, channel;
    Button authorization, send;
    ProgressBar spinner;

    //RSA
    PublicKey ServerPublicKey = null;
    PrivateKey privateKey = null;
    PublicKey publicKey = null;

    //AES
    SecretKey SecretKeyAES = null;

    //AUDIO
    AudioRecord recorder;
    Boolean recording, isSpeakerPhoneOn;
    int oldAudioMode, oldRingerMode;
    AudioManager audioManager = null;
    int SAMPLERATE = 8000;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_call_client);

        SERVER_IP = getIntent().getStringExtra(MainActivity.AddressIP);

        chatMsg = (TextView) findViewById(R.id.ChatMsgClient);
        channel = (TextView) findViewById(R.id.channelClient);
        authorization = (Button) findViewById(R.id.authorization);
        send = (Button) findViewById(R.id.send);
        spinner = (ProgressBar)findViewById(R.id.progressBar);

        spinner.setVisibility(View.GONE);

        audioManager = (AudioManager)getSystemService(Context.AUDIO_SERVICE);
        oldAudioMode = audioManager.getMode();
        oldRingerMode = audioManager.getRingerMode();
        isSpeakerPhoneOn = audioManager.isSpeakerphoneOn();

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

    public void Disconnect(View view) {
        recording = false;
        if (chatClientThread == null) {
            return;
        }
        chatClientThread.disconnect();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        audioManager.setSpeakerphoneOn(isSpeakerPhoneOn);
        audioManager.setMode(oldAudioMode);
        audioManager.setRingerMode(oldRingerMode);
    }

    public void Authorization(View view) {
        msgByte = publicKey.getEncoded();
        authorization.setVisibility(view.GONE);
        send.setVisibility(view.VISIBLE);
        spinner.setVisibility(View.VISIBLE);
    }

    public void SendMsgButton(View view) {

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

            AudioTrack at = new AudioTrack(AudioManager.STREAM_MUSIC, SAMPLERATE, AudioFormat.CHANNEL_OUT_MONO,
                    AudioFormat.ENCODING_PCM_16BIT, 1024, AudioTrack.MODE_STREAM);
            at.play();
            audioManager = (AudioManager) getSystemService(Context.AUDIO_SERVICE);
            audioManager.setSpeakerphoneOn(false);
            audioManager.setMode(AudioManager.MODE_IN_COMMUNICATION);

            byte[] encoded = null;
            byte[] sign = null;
            boolean IsVerify = false;

            try {
                socket = new Socket(dstAddress, dstPort);
                dataOutputStream = new DataOutputStream(socket.getOutputStream());
                dataInputStream = new DataInputStream(socket.getInputStream());
                dataOutputStream.writeUTF(name);
                dataOutputStream.flush();

                while (!goOut) {
                    if (dataInputStream.available() > 0) {

                        byte[] inputData = null;
                        try {
                            int length = dataInputStream.readInt(); // read length of incoming message
                            if (length > 0) {
                                inputData = new byte[length];
                                dataInputStream.readFully(inputData, 0, inputData.length);  // read the message
                            }
                        } catch (Exception e) {
                            Log.e(TAG, "Blad odebrania");
                        }

                        switch (Counter) {

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
                                    CallClient.this.runOnUiThread(new Runnable() {
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
                                byte[] audioData = functions.DecryptionAES(inputData, SecretKeyAES);
                                at.write(audioData, 0, 1024);
                                break;
                        }
                    }
                    //  WIADOMOSC DO WYSLANIA
                    if (msgByte != null) {
                        dataOutputStream.writeInt(msgByte.length); // write length of the message
                        dataOutputStream.write(msgByte);           // write the message
                        msgByte = null;
                    }
                }

            } catch (UnknownHostException e) {
                e.printStackTrace();
                final String eString = e.toString();
                CallClient.this.runOnUiThread(new Runnable() {

                    @Override
                    public void run() {
                        Toast.makeText(CallClient.this, eString, Toast.LENGTH_LONG).show();
                    }

                });
            } catch (IOException e) {
                e.printStackTrace();
                final String eString = e.toString();
                CallClient.this.runOnUiThread(new Runnable() {

                    @Override
                    public void run() {
                        Toast.makeText(CallClient.this, eString, Toast.LENGTH_LONG).show();
                    }

                });
            } finally {
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

                if (dataOutputStream != null) {
                    try {
                        dataOutputStream.close();
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

                if (dataInputStream != null) {
                    try {
                        dataInputStream.close();
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
            }

            at.stop();
            at.release();
        }
        private void disconnect() {
            goOut = true;
        }
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.ECLAIR
                && (keyCode == KeyEvent.KEYCODE_BACK)
                && event.getRepeatCount() == 0) {
            onBackPressed();
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override
    public void onBackPressed() {
        // Do nothing
    }
}