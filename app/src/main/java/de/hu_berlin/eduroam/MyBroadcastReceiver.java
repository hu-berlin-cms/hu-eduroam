package de.hu_berlin.eduroam;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiEnterpriseConfig;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.support.v4.app.NotificationCompat;
import android.support.v4.app.NotificationManagerCompat;
import android.util.Log;
import android.widget.Toast;

import java.util.Arrays;
import java.util.List;

import static android.content.Context.WIFI_SERVICE;
import static de.hu_berlin.eduroam.WiFiEduroam.surroundWithQuotes;

public class MyBroadcastReceiver extends BroadcastReceiver {
    private static final String TAG = "MyBroadcastReceiver";
    private static final String CHANNEL_ID = "de.hu_berlin.cms.hu_eduroam_notifications";

    @Override
    public void onReceive(Context context, Intent intent) {

        //check if notification needed
        List<String> ssids = Arrays.asList("eduroam", "eduroam_5GHz");

        WifiManager wifiManager = (WifiManager) context.getApplicationContext().getSystemService(WIFI_SERVICE);
        //return, if we can't check
        if (wifiManager == null) {
            Log.d(TAG, "Could not check for notification need");
            return;
        }

        List<WifiConfiguration> configs = null;
        // try to get the configured networks for 10ms
        for (int i = 0; i < 10 && configs == null; i++) {
            configs = wifiManager.getConfiguredNetworks();
            try {
                Thread.sleep(1);
            } catch (InterruptedException ignored) {
            }
        }

        if (configs == null) {
            Log.d(TAG, "Could not check for notification need");
            return;
        }

        // loop through networks and check for eduroam configurations
        // if there is one with a new anonymous identity, the user doesn't need to do anything
        boolean eduroam_found = false;
        for (WifiConfiguration config : configs) {
            for (String ssid : ssids) {
                if (config.SSID.equals(surroundWithQuotes(ssid))) {
                    eduroam_found = true;
                    if (config.enterpriseConfig == null || config.enterpriseConfig.getAnonymousIdentity() == null || config.enterpriseConfig.getAnonymousIdentity().contains("wlan.hu-berlin.de")) {
                        Log.d(TAG, "Notification not needed");
                        return;
                    }
                }
            }
        }

        // no notification on fresh install
        if (!eduroam_found) {
            Log.d(TAG, "No notification on fresh install");
            return;
        }

        createNotificationChannel(context);

        // open App, when tapping on notification
        Intent aintent = new Intent(context, WiFiEduroam.class);
        aintent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        PendingIntent pendingIntent = PendingIntent.getActivity(context, 0, aintent, 0);


        NotificationCompat.Builder mBuilder = new NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_baseline_notification_important_24px)
                .setContentTitle(context.getString(R.string.notification_title))
                .setContentText(context.getString(R.string.notification_text))
                .setStyle(new NotificationCompat.BigTextStyle()
                        .bigText(context.getString(R.string.notification_text)))
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true);

        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(context);

        // notificationId is a unique int for each notification that you must define
        notificationManager.notify(1, mBuilder.build());

        /*StringBuilder sb = new StringBuilder();
        sb.append("Action: " + intent.getAction() + "\n");
        sb.append("URI: " + intent.toUri(Intent.URI_INTENT_SCHEME).toString() + "\n");
        String log = sb.toString();
        Log.d(TAG, log);
        Toast.makeText(context, log, Toast.LENGTH_LONG).show();*/
    }

    private void createNotificationChannel(Context context) {
        Log.d(TAG, "Creating notification channel");
        // Create the NotificationChannel, but only on API 26+ because
        // the NotificationChannel class is new and not in the support library
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            CharSequence name = context.getString(R.string.channel_name);
            String description = context.getString(R.string.channel_description);
            int importance = NotificationManager.IMPORTANCE_DEFAULT;
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
            channel.setDescription(description);
            // Register the channel with the system; you can't change the importance
            // or other notification behaviors after this
            NotificationManager notificationManager = context.getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }
}
