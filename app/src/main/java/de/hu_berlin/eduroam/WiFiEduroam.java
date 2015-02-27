/* Copyright 2013 Wilco Baan Hofman <wilco@baanhofman.nl>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package de.hu_berlin.eduroam;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiEnterpriseConfig;
import android.net.wifi.WifiEnterpriseConfig.Eap;
import android.net.wifi.WifiEnterpriseConfig.Phase2;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.security.KeyChain;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.text.DateFormat;
import java.util.TimeZone;

// API level 18 and up

public class WiFiEduroam extends Activity {
    private static final String INT_EAP = "eap";
    private static final String INT_CA_CERT = "ca_cert";
    private static final String INT_SUBJECT_MATCH = "subject_match";
    private static final String INT_ANONYMOUS_IDENTITY = "anonymous_identity";
    private static final String INT_ENTERPRISEFIELD_NAME = "android.net.wifi.WifiConfiguration$EnterpriseField";
    private static final String INT_PHASE2 = "phase2";
    private static final String INT_PASSWORD = "password";
    private static final String INT_IDENTITY = "identity";
    private static final String TAG = "hu-eduroam";

    // Because android.security.Credentials cannot be resolved...
    private static final String INT_KEYSTORE_URI = "keystore://";
    private static final String INT_CA_PREFIX = INT_KEYSTORE_URI + "CACERT_";

    private Handler mHandler = new Handler();
    private EditText username;
    private EditText password;
    private String ca;
    private String ca_name = "tcom";
    private String subject_match = "-radius.cms.hu-berlin.de";
    private String realm = "@cms.hu-berlin.de";
    private List<String> ssids = Arrays.asList("eduroam", "eduroam_5GHz");
    private Toast toast = null;

    // Called when the activity is first created.
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.logon);

        // check if eduroam already exists and adjust button text
        if (eduroamExists()) {
            ((android.widget.Button) findViewById(R.id.button1)).setText(R.string.Install_exists);
        }

        username = (EditText) findViewById(R.id.username);
        password = (EditText) findViewById(R.id.password);

        final Button myButton = (Button) findViewById(R.id.button1);
        if (myButton == null)
            throw new RuntimeException("button1 not found. Odd");


        myButton.setOnClickListener(new Button.OnClickListener() {
            public void onClick(View _v) {
                // disable button when running
                myButton.setEnabled(false);

                try {
                    updateStatus(getString(R.string.STATUS_INSTALL_PROFILE));
                    InputStream caCertInputStream = getResources().openRawResource(R.raw.deutsche_telekom_root_ca_2);
                    ca = convertStreamToString(caCertInputStream);

                    if (android.os.Build.VERSION.SDK_INT >= 11 && android.os.Build.VERSION.SDK_INT <= 17) {
                        // 11 == 3.0 Honeycomb 02/2011, 17 == 4.2 Jelly Bean
                        installCertificates();
                    } else if (android.os.Build.VERSION.SDK_INT >= 18) {
                        // new features since 4.3
                        unlockCredentialStorage();
                    } else {
                        throw new RuntimeException("What version is this?! API Mismatch");
                    }
                } catch (RuntimeException e) {
                    updateStatus("Runtime Error: " + e.getMessage());
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void unlockCredentialStorage() {
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB) {
                startActivityForResult(new Intent("android.credentials.UNLOCK"), 2);
            } else {
                startActivityForResult(new Intent("com.android.credentials.UNLOCK"), 2);
            }
        } catch (ActivityNotFoundException e) {
            Log.e(TAG, "No UNLOCK activity: " + e.getMessage(), e);
        }
    }

    private boolean isDeviceSecured() {
        // use appropriate API method where possible
        if (android.os.Build.VERSION.SDK_INT >= 16) {
            // Get a reference to the KEYGUARD_SERVICE
            KeyguardManager keyguardManager = (KeyguardManager) this.getSystemService(Context.KEYGUARD_SERVICE);
            // Query the keyguard security
            return keyguardManager.isKeyguardSecure();
        } else {
            // source: http://stackoverflow.com/a/25291077/1381638
            // could check against isLockPasswordEnabled() and isLockPatternEnabled()
            // but PASSWORD_QUALITY_NUMERIC seems fine. Couldn't enter a lower quality password on my Android 4.4.4
            String LOCKSCREEN_UTILS = "com.android.internal.widget.LockPatternUtils";
            try {
                Class<?> lockUtilsClass = Class.forName(LOCKSCREEN_UTILS);
                // "this" is a Context, in my case an Activity
                Object lockUtils = lockUtilsClass.getConstructor(Context.class).newInstance(this);

                Method method = lockUtilsClass.getMethod("getActivePasswordQuality");

                int lockProtectionLevel = (Integer) method.invoke(lockUtils); // Thank you esme_louise for the cast hint

                if (lockProtectionLevel >= DevicePolicyManager.PASSWORD_QUALITY_NUMERIC) {
                    return true;
                }
            } catch (Exception e) {
                Log.e(TAG, "ex:" + e);
            }
            return false;
        }
    }

    private void saveWifiConfig() {
        WifiManager wifiManager = (WifiManager) this.getSystemService(WIFI_SERVICE);
        wifiManager.setWifiEnabled(true);

        // wait 5 seconds for wifi to get enabled
        // busy wait is bad, but I didn't find a better approach
        for (int i = 0; i < 50 && !wifiManager.isWifiEnabled(); i++) {
            if (i == 10)
                updateStatus(getString(R.string.STATUS_WIFI_WAIT));
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                continue;
            }
        }

        if (!wifiManager.isWifiEnabled()) {
            showDialogAndFinish(getString(R.string.INST_ABORTED_WIFI_ENABLE));
            Log.d(TAG, "Couldn't activate wifi.");
            return;
        }

        WifiConfiguration currentConfig = new WifiConfiguration();

        List<WifiConfiguration> configs = null;
        // try to get the configured networks for 10ms
        for (int i = 0; i < 10 && configs == null; i++) {
            configs = wifiManager.getConfiguredNetworks();
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                continue;
            }
        }

        // Remove existing eduroam profiles
        // There could possibly be more than one "eduroam" profile, which could cause errors
        // We don't know which wrong settings existing profiles contain, just remove them
        if (configs != null) {
            for (WifiConfiguration config : configs) {
                for (String ssid : ssids) {
                    if (config.SSID.equals(surroundWithQuotes(ssid))) {
                        wifiManager.removeNetwork(config.networkId);
                    }
                }
            }
        }

        currentConfig.hiddenSSID = false;
        currentConfig.priority = 40;
        currentConfig.status = WifiConfiguration.Status.DISABLED;

        currentConfig.allowedKeyManagement.clear();
        currentConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);

        // GroupCiphers (Allow only secure ciphers)
        currentConfig.allowedGroupCiphers.clear();
        currentConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        //currentConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        //currentConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);

        // PairwiseCiphers (CCMP = WPA2 only)
        currentConfig.allowedPairwiseCiphers.clear();
        currentConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);

        // Authentication Algorithms (OPEN)
        currentConfig.allowedAuthAlgorithms.clear();
        currentConfig.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);

        // Protocols (RSN/WPA2 only)
        currentConfig.allowedProtocols.clear();
        currentConfig.allowedProtocols.set(WifiConfiguration.Protocol.RSN);

        // Enterprise Settings
        HashMap<String, String> configMap = new HashMap<String, String>();
        configMap.put(INT_SUBJECT_MATCH, subject_match);
        configMap.put(INT_ANONYMOUS_IDENTITY, "anonymous" + realm);
        configMap.put(INT_EAP, "TTLS");
        configMap.put(INT_PHASE2, "auth=PAP");
        configMap.put(INT_CA_CERT, INT_CA_PREFIX + ca_name);
        configMap.put(INT_PASSWORD, password.getText().toString());
        configMap.put(INT_IDENTITY, username.getText().toString());

        if (android.os.Build.VERSION.SDK_INT >= 11 && android.os.Build.VERSION.SDK_INT <= 17) {
            applyAndroid4_42EnterpriseSettings(currentConfig, configMap);
        } else if (android.os.Build.VERSION.SDK_INT >= 18) {
            applyAndroid43EnterpriseSettings(currentConfig, configMap);
        } else {
            throw new RuntimeException("API version mismatch!");
        }

        // add our new networks
        for (String ssid : ssids) {
            currentConfig.SSID = surroundWithQuotes(ssid);
            int networkId = wifiManager.addNetwork(currentConfig);
            if (networkId < 0) {
                // it didn't work out

                // cleanup after install try
                cleanupAfterInstallRun();
                installationAborted();
                return;
            }
            wifiManager.enableNetwork(networkId, false);
        }

        wifiManager.saveConfiguration();

        // everything went fine
        // cleanup after install
        cleanupAfterInstallRun();
        installationFinished();
    }


    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private void applyAndroid43EnterpriseSettings(WifiConfiguration currentConfig, HashMap<String, String> configMap) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(Base64.decode(ca.replaceAll("-----(BEGIN|END) CERTIFICATE-----", ""), Base64.DEFAULT));
            X509Certificate caCert = (X509Certificate) certFactory.generateCertificate(in);

            WifiEnterpriseConfig enterpriseConfig = new WifiEnterpriseConfig();
            enterpriseConfig.setPhase2Method(Phase2.PAP);
            enterpriseConfig.setAnonymousIdentity(configMap.get(INT_ANONYMOUS_IDENTITY));
            enterpriseConfig.setEapMethod(Eap.TTLS);

            enterpriseConfig.setCaCertificate(caCert);
            enterpriseConfig.setSubjectMatch(configMap.get(INT_SUBJECT_MATCH));
            enterpriseConfig.setIdentity(configMap.get(INT_IDENTITY));
            enterpriseConfig.setPassword(configMap.get(INT_PASSWORD));
            currentConfig.enterpriseConfig = enterpriseConfig;

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    // Step 1 for android 4.0 - 4.2
    private void installCertificates() {
        // Install the CA certificate
        updateStatus(getString(R.string.STATUS_IMPORT_CA_CERT));
        Intent intent = KeyChain.createInstallIntent();
        intent.putExtra(KeyChain.EXTRA_NAME, ca_name);
        intent.putExtra(KeyChain.EXTRA_CERTIFICATE, Base64.decode(ca.replaceAll("-----(BEGIN|END) CERTIFICATE-----", ""), Base64.DEFAULT));
        startActivityForResult(intent, 1);
    }


    @Override
    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    // Step 2 for android 4.0 - 4.2; dispatcher for later steps
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        if (requestCode == 1 && resultCode != RESULT_OK) {
            updateStatus(getString(R.string.INST_ABORTED));
            return;
        }

        Log.d(TAG, "device secured?: " + this.isDeviceSecured());

        // save wifi config in worker thread
        new Thread(new Runnable() {
            @Override
            public void run() {
                saveWifiConfig();
            }
        }).start();
    }

    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    // Last step for android 4.0 - 4.2, called from saveWifiConfig
    private void applyAndroid4_42EnterpriseSettings(WifiConfiguration currentConfig, HashMap<String, String> configMap) {
        // NOTE: This code is mighty ugly, but reflection is the only way to get the methods we need
        // Get the enterprise class via reflection
        Class<?>[] wcClasses = WifiConfiguration.class.getClasses();
        Class<?> wcEnterpriseField = null;

        for (Class<?> wcClass : wcClasses) {
            if (wcClass.getName().equals(
                    INT_ENTERPRISEFIELD_NAME)) {
                wcEnterpriseField = wcClass;
                break;
            }
        }
        if (wcEnterpriseField == null) {
            throw new RuntimeException("There is no enterprisefield class.");
        }

        // Get the setValue handler via reflection
        Method wcefSetValue = null;
        for (Method m : wcEnterpriseField.getMethods()) {
            if (m.getName().equals("setValue")) {
                wcefSetValue = m;
                break;
            }
        }
        if (wcefSetValue == null) {
            throw new RuntimeException("There is no setValue method.");
        }

        // Fill fields from the HashMap
        Field[] wcefFields = WifiConfiguration.class.getFields();
        for (Field wcefField : wcefFields) {
            if (configMap.containsKey(wcefField.getName())) {
                try {
                    wcefSetValue.invoke(wcefField.get(currentConfig),
                            configMap.get(wcefField.getName()));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.options_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        Builder builder = new AlertDialog.Builder(this);
        switch (item.getItemId()) {
            case R.id.about:
                PackageInfo pi = null;
                try {
                    pi = getPackageManager().getPackageInfo(getClass().getPackage().getName(), 0);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                builder.setTitle(getString(R.string.ABOUT_TITLE));
                builder.setMessage(getString(R.string.ABOUT_CONTENT) +
                        "\n\n" + pi.packageName + "\n" +
                        "V" + pi.versionName +
                        "C" + pi.versionCode);
                builder.setPositiveButton(getString(android.R.string.ok), null);
                builder.show();

                return true;

            case R.id.troubleshoot:
                builder.setTitle(getString(R.string.TROUBLESHOOT_TITLE));
                builder.setMessage(getString(R.string.TROUBLESHOOT_CONTENT) +
                        getTroubleshootingInfo());
                builder.setPositiveButton(getString(android.R.string.ok), null);
                builder.show();

                return true;

            case R.id.exit:
                System.exit(0);
        }
        return false;
    }


    /* Update the status in the main thread */
    protected void updateStatus(final String text) {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                System.out.println(text);
                if (toast != null)
                    toast.cancel();
                toast = Toast.makeText(getBaseContext(), text, Toast.LENGTH_LONG);
                toast.show();
            }
        });
    }


    private void installationFinished() {
        updateStatus(getString(R.string.INST_FINISHED));
        showDialogAndFinish(getString(R.string.INST_FINISHED));
    }

    private void installationAborted() {
        updateStatus(getString(R.string.INST_ABORTED));
        if (isDeviceSecured()) {
            showDialogAndFinish(getString(R.string.INST_ABORTED));
        } else {
            showDialogAndFinish(getString(R.string.INST_ABORTED_LOCK));
        }
    }

    private boolean eduroamExists() {
        WifiManager wifiManager = (WifiManager) this.getSystemService(WIFI_SERVICE);
        List<WifiConfiguration> configs = null;
        // try to get the configured networks for 10ms
        for (int i = 0; i < 10 && configs == null; i++) {
            configs = wifiManager.getConfiguredNetworks();
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                continue;
            }
        }

        // Are there "eduroam" profiles?
        if (configs != null) {
            for (WifiConfiguration config : configs) {
                if (config.SSID.equals(surroundWithQuotes(ssids.get(0)))) {
                    return true;
                }
            }
        }

        return false;
    }

    private void showDialogAndFinish(final String msg) {
        mHandler.post(new Runnable() {
            public void run(){
              AlertDialog.Builder dlgAlert  = new AlertDialog.Builder(WiFiEduroam.this);
              dlgAlert.setMessage(msg);
              dlgAlert.setPositiveButton(getString(android.R.string.ok), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                  finish();
                }
              });
              dlgAlert.create().show();
            }
        });
    }

    private void cleanupAfterInstallRun() {
        mHandler.post(new Runnable() {
            public void run(){
                // clear password field
                password.setText("");

                // reenable button
                final Button myButton = (Button) findViewById(R.id.button1);
                myButton.setEnabled(true);
            }
        });
    }

    static String surroundWithQuotes(String string) {
        return "\"" + string + "\"";
    }

    // read file into string
    // source: http://stackoverflow.com/a/5445161
    static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    private String getTroubleshootingInfo() {
        // get mac address
        WifiManager wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        wifiManager.setWifiEnabled(true);

        String result = "";

        // wait 2 seconds for wifi to get enabled
        // busy wait is bad, but I didn't find a better approach
        for (int i = 0; i < 20 && !wifiManager.isWifiEnabled(); i++) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                continue;
            }
        }

        if (wifiManager.isWifiEnabled()) {
            WifiInfo connInfo = wifiManager.getConnectionInfo();

            DateFormat time_fmt = DateFormat.getDateTimeInstance();
            time_fmt.setTimeZone(TimeZone.getTimeZone("UTC")); // always use UTC
            String cur_time = time_fmt.format(new Date());
            result += "\n" + getString(R.string.TIME) + ": " + cur_time + " UTC";

            String macAddress = connInfo.getMacAddress();
            if (macAddress == null) {
                macAddress = getString(R.string.ERR_NOT_FOUND);
            }
            result += "\n" + getString(R.string.MAC_ADDRESS) + ": " + macAddress;

            String ssid = connInfo.getSSID();
            if (ssid == null) {
                ssid = getString(R.string.ERR_NOT_FOUND);
            }
            result += "\n" + getString(R.string.SSID) + ": " + ssid;

            String bssid = connInfo.getBSSID();
            if (bssid == null) {
                bssid = getString(R.string.ERR_NOT_FOUND);
            }
            result += "\n" + getString(R.string.AP) + ": " + bssid;
        } else {
            result = "\n" + getString(R.string.ERR_NO_TROUBLESHOOT);
        }

        return result;
    }

}
