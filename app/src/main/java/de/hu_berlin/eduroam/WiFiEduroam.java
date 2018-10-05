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
 *
 *  This file has been modified by Enno Gröper.
 */

package de.hu_berlin.eduroam;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.app.KeyguardManager;
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
import android.provider.Settings;
import android.text.format.Formatter;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
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
    private static final String INT_ALT_SUBJECT_MATCH = "alt_subject_match";
    private static final String INT_ANONYMOUS_IDENTITY = "anonymous_identity";
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
    private String ca_name = "tcom2ndgen";
    private String subject_match = "-radius.cms.hu-berlin.de";
    private String alt_subject_match = "DNS:srv1-radius.cms.hu-berlin.de;DNS:srv2-radius.cms.hu-berlin.de";
    private String realm = "@wlan.hu-berlin.de";
    private List<String> ssids = Arrays.asList("eduroam", "eduroam_5GHz");
    private List<String> valid_full_domains = Arrays.asList("physik.hu-berlin.de", "mathematik.hu-berlin.de", "informatik.hu-berlin.de");
    private List<String> valid_short_domains = Arrays.asList("physik", "mathematik", "informatik");
    private Toast toast = null;
    private boolean display_lock_exists = false;

    // Called when the activity is first created.
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.logon);

        // check if eduroam already exists and adjust button text
        if (eduroamExists()) {
            ((android.widget.Button) findViewById(R.id.button1)).setText(R.string.Install_exists);
        }

        username = findViewById(R.id.username);
        password = findViewById(R.id.password);

        final Button myButton = findViewById(R.id.button1);
        if (myButton == null)
            throw new RuntimeException("button1 not found. Odd");


        myButton.setOnClickListener(new Button.OnClickListener() {
            public void onClick(View _v) {
                // disable button when running
                myButton.setEnabled(false);

                try {
                    updateStatus(getString(R.string.STATUS_INSTALL_PROFILE));
                    InputStream caCertInputStream = getResources().openRawResource(R.raw.t_telesec_globalroot_class_2);
                    ca = convertStreamToString(caCertInputStream);

                    if (isDeviceSecured()) {
                        display_lock_exists = true;
                    }

                    unlockCredentialStorage();
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
            startActivityForResult(new Intent("com.android.credentials.UNLOCK"), 2);
        } catch (ActivityNotFoundException e) {
            Log.e(TAG, "No UNLOCK activity: " + e.getMessage(), e);
        }
    }

    private boolean isDeviceSecured() {
        // Get a reference to the KEYGUARD_SERVICE
        KeyguardManager keyguardManager = (KeyguardManager) this.getSystemService(Context.KEYGUARD_SERVICE);
        // Query the keyguard security
        return (keyguardManager != null) && keyguardManager.isKeyguardSecure();
    }

    private boolean containsDomain(String username, List<String> domains) {
        for(String domain: domains) {
            if (username.contains(domain)) {
                return true;
            }
        }
        return false;  // no match
    }

    /* append full domain to all usernames (inner identity) to circumvent problems on broken devices (i.e. Wiko...) */
    private String fix_username(String username) {
        if (!username.contains("@")) {
            // cms account without domain
            return username + "@wlan.hu-berlin.de";
        } else if (containsDomain(username, valid_full_domains)) {
            // username contains old full external domain (physik, ...)
            // => insert wlan subdomain
            String[] parts = username.split("\\.hu-berlin\\.de");
            return parts[0] + ".wlan.hu-berlin.de";
        } else if (username.contains("@cms.hu-berlin.de")) {
            // old full domain for CMS accounts; => replace
            String[] parts = username.split("@");
            return parts[0] + "@wlan.hu-berlin.de";
        } else if (containsDomain(username, valid_short_domains)) {
            // username contains short domain
            return username + ".wlan.hu-berlin.de";
        } else {
            return username;
        }
    }

    private void saveWifiConfig() {
        WifiManager wifiManager = (WifiManager) this.getApplicationContext().getSystemService(WIFI_SERVICE);
        if (wifiManager == null) {
            updateStatus(getString(R.string.ERR_SAVE_CONFIG));
            return;
        }
        wifiManager.setWifiEnabled(true);

        // wait 5 seconds for wifi to get enabled
        // busy wait is bad, but I didn't find a better approach
        for (int i = 0; i < 50 && !wifiManager.isWifiEnabled(); i++) {
            if (i == 10)
                updateStatus(getString(R.string.STATUS_WIFI_WAIT));
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
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
            } catch (InterruptedException ignored) {
            }
        }

        // Remove existing eduroam profiles
        // There could possibly be more than one "eduroam" profile, which could cause errors
        // We don't know which wrong settings existing profiles contain, just remove them
        if (configs != null) {
            for (WifiConfiguration config : configs) {
                for (String ssid : ssids) {
                    if (config.SSID.equals(surroundWithQuotes(ssid))) {
                        if (!wifiManager.removeNetwork(config.networkId)) {
                            showWifiSettingsDialog(config.SSID, ssids);
                            return;
                        }
                    }
                }
            }
        }

        currentConfig.hiddenSSID = false;
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
        HashMap<String, String> configMap = new HashMap<>();
        configMap.put(INT_SUBJECT_MATCH, subject_match);
        configMap.put(INT_ALT_SUBJECT_MATCH, alt_subject_match);
        configMap.put(INT_ANONYMOUS_IDENTITY, "anonymous" + realm);
        configMap.put(INT_EAP, "TTLS");
        configMap.put(INT_PHASE2, "auth=PAP");
        configMap.put(INT_CA_CERT, INT_CA_PREFIX + ca_name);
        configMap.put(INT_PASSWORD, password.getText().toString());
        configMap.put(INT_IDENTITY, fix_username(username.getText().toString().trim()));

        applyEnterpriseSettings(currentConfig, configMap);

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

        if (Build.VERSION.SDK_INT < 26) {
            saveWififConfigInManager(wifiManager);
        }

        // everything went fine
        // cleanup after install
        cleanupAfterInstallRun();
        installationFinished(!display_lock_exists && android.os.Build.VERSION.SDK_INT >= 23);
    }


    private void applyEnterpriseSettings(WifiConfiguration currentConfig, HashMap<String, String> configMap) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(Base64.decode(ca.replaceAll("-----(BEGIN|END) CERTIFICATE-----", ""), Base64.DEFAULT));
            X509Certificate caCert = (X509Certificate) certFactory.generateCertificate(in);

            WifiEnterpriseConfig enterpriseConfig = new WifiEnterpriseConfig();
            enterpriseConfig.setPhase2Method(Phase2.PAP);
            enterpriseConfig.setAnonymousIdentity(configMap.get(INT_ANONYMOUS_IDENTITY));
            enterpriseConfig.setEapMethod(Eap.TTLS);

            enterpriseConfig.setCaCertificate(caCert);

            if (android.os.Build.VERSION.SDK_INT >= 23) {
                enterpriseConfig.setAltSubjectMatch(configMap.get(INT_ALT_SUBJECT_MATCH));
            } else {
                setSubjectMatchLegacy(enterpriseConfig, configMap.get(INT_SUBJECT_MATCH));
            }
            enterpriseConfig.setIdentity(configMap.get(INT_IDENTITY));
            enterpriseConfig.setPassword(configMap.get(INT_PASSWORD));
            currentConfig.enterpriseConfig = enterpriseConfig;

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("deprecation")
    private void setSubjectMatchLegacy(WifiEnterpriseConfig cfg, String value) {
        cfg.setSubjectMatch(value);
    }

    @SuppressWarnings("deprecation")
    private void saveWififConfigInManager(WifiManager wifiManager) {
        wifiManager.saveConfiguration();
    }

    @Override
    // dispatcher for later steps
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        /*
         * requestCode 1: unused
         * requestCode 2: unlock credential storage
         * requestCode 3: open wifi settings dialog (help user remove wifi profiles we aren't allowed to remove)
         * requestCode 4: open security settings dialog to help user removing screen lock, if android supports it
                          and we are the only reason for the screen lock
         */
        // after opening security settings dialog
        if (requestCode == 4) {
            finish();
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
                if (pi == null) {
                    builder.setMessage(getString(R.string.ABOUT_CONTENT));
                } else {
                    builder.setMessage(getString(R.string.ABOUT_CONTENT) +
                            "\n\n" + pi.packageName + "\n" +
                            "V" + pi.versionName +
                            "C" + pi.versionCode);
                }
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


    private void installationFinished(boolean new_lock) {
        updateStatus(getString(R.string.INST_FINISHED));
        if (new_lock) {
            showDisplayLockSettingsDialog();
        } else {
            showDialogAndFinish(getString(R.string.INST_FINISHED));
        }
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
        WifiManager wifiManager = (WifiManager) this.getApplicationContext().getSystemService(WIFI_SERVICE);
        List<WifiConfiguration> configs = null;
        // try to get the configured networks for 10ms
        for (int i = 0; i < 10 && configs == null; i++) {
            configs = wifiManager != null ? wifiManager.getConfiguredNetworks() : null;
            try {
                Thread.sleep(1);
            } catch (InterruptedException ignored) {
            }
        }

        // Are there "eduroam" profiles?
        if (configs != null) {
            for (WifiConfiguration config : configs) {
                if (config.SSID != null && config.SSID.equals(surroundWithQuotes(ssids.get(0)))) {
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
              if (!isFinishing())
                  dlgAlert.create().show();
            }
        });
    }

    private void showDisplayLockSettingsDialog() {
        mHandler.post(new Runnable() {
            public void run(){
                final AlertDialog.Builder dlgAlert  = new AlertDialog.Builder(WiFiEduroam.this);
                dlgAlert.setMessage(getString(R.string.INST_FINISHED_REMOVE_LOCK));
                dlgAlert.setPositiveButton(getString(R.string.SECURITY_SETTINGS), new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        dialog.dismiss();
                        startActivityForResult(new Intent(Settings.ACTION_SECURITY_SETTINGS), 4);
                    }
                });
                dlgAlert.setNegativeButton(getString(R.string.EXIT), new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        finish();
                    }
                });
                dlgAlert.create().show();
            }
        });
    }

    private void showWifiSettingsDialog(final String cur_ssid, final List<String> ssids) {
        mHandler.post(new Runnable() {
            public void run(){
                final AlertDialog.Builder dlgAlert  = new AlertDialog.Builder(WiFiEduroam.this);
                dlgAlert.setMessage(String.format(getString(R.string.DLG_WIFI_REMOVE), cur_ssid,  android.text.TextUtils.join("\n", ssids)));
                dlgAlert.setPositiveButton(getString(R.string.WIFI_SETTINGS), new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        dialog.dismiss();
                        startActivityForResult(new Intent(Settings.ACTION_WIFI_SETTINGS), 3);
                    }
                });
                dlgAlert.setNegativeButton(getString(R.string.ABORT), new DialogInterface.OnClickListener() {
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
                final Button myButton = findViewById(R.id.button1);
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

    @SuppressLint("HardwareIds")
    private String getTroubleshootingInfo() {
        // get mac address
        WifiManager wifiManager = (WifiManager) this.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wifiManager == null)
            return getString(R.string.ERR_NO_TROUBLESHOOT);

        wifiManager.setWifiEnabled(true);

        String result = "";

        // wait 2 seconds for wifi to get enabled
        // busy wait is bad, but I didn't find a better approach
        for (int i = 0; i < 20 && !wifiManager.isWifiEnabled(); i++) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
            }
        }

        if (wifiManager.isWifiEnabled()) {
            WifiInfo connInfo = wifiManager.getConnectionInfo();

            DateFormat time_fmt = DateFormat.getDateTimeInstance();
            time_fmt.setTimeZone(TimeZone.getTimeZone("UTC")); // always use UTC
            String cur_time = time_fmt.format(new Date());
            result += "\n" + getString(R.string.TIME) + ": " + cur_time + " UTC";

            // get uid
            String uid = null;
            int netid = connInfo.getNetworkId();
            if (netid > -1) {
                // we are connected
                List<WifiConfiguration> configs = null;
                // try to get the configured networks for 10ms
                for (int i = 0; i < 10 && configs == null; i++) {
                    configs = wifiManager.getConfiguredNetworks();
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException ignored) {
                    }
                }

                if (configs != null) {
                    for (WifiConfiguration config : configs) {
                        if (config.networkId == netid) {
                            uid = config.enterpriseConfig.getIdentity();
                            break;
                        }
                    }
                }
            }
            if (uid == null || uid.equals("")) {
                uid = getString(R.string.ERR_NOT_FOUND);
            }
            result += "\n" + getString(R.string.uid) + ": " + uid;



            // deprecated but easy, see http://stackoverflow.com/q/16730711/1381638
            int ip = connInfo.getIpAddress();
            @SuppressWarnings("deprecation")
            String ipAddress = Formatter.formatIpAddress(ip);
            if (ipAddress == null || ipAddress.equals("0.0.0.0")) {
                ipAddress = getString(R.string.ERR_NOT_FOUND);
            }
            result += "\n" + getString(R.string.IP_ADDRESS) + ": " + ipAddress;


            String macAddress = null;
            if (android.os.Build.VERSION.SDK_INT < 23) {
                macAddress = connInfo.getMacAddress();
            } else {
                // FIXME https://stackoverflow.com/a/39792022/1381638
                // dirty hack for Marshmallow
                try {
                    File file = new File("/sys/class/net/wlan0/address");
                    BufferedReader br = new BufferedReader(new FileReader(file));
                    macAddress = br.readLine();
                    br.close() ;
                } catch (IOException e) {
                    // at least we tried...
                }
            }

            if (macAddress == null || macAddress.equals("02:00:00:00:00:00")) {
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
