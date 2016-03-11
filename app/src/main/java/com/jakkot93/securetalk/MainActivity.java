package com.jakkot93.securetalk;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

public class MainActivity extends Activity {

    public final static String AddressIP = "com.jakkot93.security.AddressIP";
    int code;
    EditText EdT_IP;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final Button BtnJoin = (Button) findViewById(R.id.join);
        final Button BtnCreate = (Button) findViewById(R.id.create);
        final Button BtnMsg = (Button) findViewById(R.id.messenger);
        final Button BtnCall = (Button) findViewById(R.id.phone_call);
        final Button BtnStart = (Button) findViewById(R.id.start);

        final TextView Tv2 = (TextView) findViewById(R.id.tv2);
        final TextView Tv3 = (TextView) findViewById(R.id.tv3);

        EdT_IP = (EditText) findViewById(R.id.ip);


        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            String alias = "SecureTalk";

            // Create the keys if necessary
            if (!keyStore.containsAlias(alias)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(this)
                        .setAlias(alias)
                        .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                generator.initialize(spec);

                KeyPair keyPair = generator.generateKeyPair();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }


        BtnJoin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                BtnJoin.setEnabled(false);
                BtnCreate.setEnabled(true);
                BtnCall.setEnabled(true);
                BtnMsg.setEnabled(true);
                Tv2.setVisibility(View.VISIBLE);
                BtnMsg.setVisibility(View.VISIBLE);
                BtnCall.setVisibility(View.VISIBLE);
                Tv3.setVisibility(View.VISIBLE);
                EdT_IP.setVisibility(View.VISIBLE);
                BtnStart.setVisibility(View.INVISIBLE);

                code = 0;
            }
        });

        BtnCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                BtnCreate.setEnabled(false);
                BtnJoin.setEnabled(true);
                BtnCall.setEnabled(true);
                BtnMsg.setEnabled(true);
                Tv2.setVisibility(View.VISIBLE);
                BtnMsg.setVisibility(View.VISIBLE);
                BtnCall.setVisibility(View.VISIBLE);
                Tv3.setVisibility(View.INVISIBLE);
                EdT_IP.setVisibility(View.INVISIBLE);
                BtnStart.setVisibility(View.INVISIBLE);

                code = 2;
            }
        });

        BtnMsg.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                BtnCall.setEnabled(false);
                BtnMsg.setEnabled(false);
                BtnStart.setVisibility(View.VISIBLE);

                code += 1;
            }
        });

        BtnCall.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                BtnCall.setEnabled(false);
                BtnMsg.setEnabled(false);
                BtnStart.setVisibility(View.VISIBLE);

                code += 2;
            }
        });
    }

    public void StartApp(View view) {
        String addrIP;
        Intent intent = new Intent(this, MainActivity.class);
        switch (code){

            case 1:
                intent = new Intent(this, ChatClient.class);
                addrIP = EdT_IP.getText().toString();
                if(TextUtils.isEmpty(addrIP)) {
                    Toast.makeText(getApplicationContext(), "Enter the IP address !!!", Toast.LENGTH_SHORT).show();
                    return;
                }
                else {
                    intent.putExtra(AddressIP, addrIP);
                }
                break;
            case 2:
                intent = new Intent(this, CallClient.class);
                addrIP = EdT_IP.getText().toString();
                if(TextUtils.isEmpty(addrIP)) {
                    Toast.makeText(getApplicationContext(), "Enter the IP address !!!", Toast.LENGTH_SHORT).show();
                    return;
                }
                else {
                    intent.putExtra(AddressIP, addrIP);
                }
                break;
            case 3:
                intent = new Intent(this, ChatServer.class);
                break;
            case 4:
                intent = new Intent(this, CallServer.class);
                break;
        }
        startActivity(intent);
        finish();
    }
}
