package com.example.auth.app.main;
/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */
import android.app.ActionBar;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Fragment;
import android.app.FragmentManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.os.Vibrator;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.ArrayAdapter;

import com.example.auth.app.fragments.ArchiveFragment;
import com.example.auth.app.fragments.ConsolePopup;
import com.example.auth.app.fragments.KeyListFragment;
import com.example.auth.app.fragments.TicketFragment;
import com.example.auth.app.fragments.ToolsFragment;
import com.example.auth.app.ulctools.Reader;
import com.example.vaarajer1.auth.R;

import java.util.Calendar;


public class MyActivity extends Activity implements ActionBar.OnNavigationListener {

    private static final String STATE_SELECTED_NAVIGATION_ITEM = "selected_navigation_item";
    public static FileManager fileManager;
    public static boolean autoAuth = true;
    public static Context outer;

    // Fragments
    public static FragmentManager fm;
    public static boolean nfcA_available = false;
    private static ToolsFragment toolsFragment;
    private static TicketFragment ticketFragment;
    private static KeyListFragment keyList;
    private static ArchiveFragment archiveFragment;
    private static MenuItem console_button;
    private static Vibrator vibrator;
    private NfcAdapter adapter;
    private PendingIntent pendingIntent;
    private IntentFilter[] filters;
    private String[][] techLists;
    private Context context;
    private ConsolePopup consoleWindow = new ConsolePopup();

    public static void showConsoleHint() {
        console_button.setIcon(R.drawable.ic_console_hint);

    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_my);

        vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);

        context = getApplicationContext();
        outer = context;

        fileManager = new FileManager();
        FileManager.getKeys(outer);
        fm = getFragmentManager();

        adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter == null || !adapter.isEnabled()) {
            promptNfc();
        }
        pendingIntent = PendingIntent.getActivity(this, 0, new Intent(this,
                getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
        try {
            ndef.addDataType("*/*");
        } catch (IntentFilter.MalformedMimeTypeException e) {
            throw new RuntimeException("fail", e);
        }
        filters = new IntentFilter[]{ndef,};

        techLists = new String[][]{new String[]{NfcA.class.getName()}};

        // Set up the action bar to show a dropdown list.
        final ActionBar actionBar = getActionBar();
        actionBar.setDisplayShowTitleEnabled(false);
        actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_LIST);

        toolsFragment = new ToolsFragment();
        ticketFragment = new TicketFragment();
        keyList = new KeyListFragment();
        archiveFragment = new ArchiveFragment();

        // Set up the dropdown list navigation in the action bar.
        actionBar.setListNavigationCallbacks(
                // Specify a SpinnerAdapter to populate the dropdown list.
                new ArrayAdapter<String>(
                        actionBar.getThemedContext(),
                        android.R.layout.simple_list_item_1,
                        android.R.id.text1,
                        new String[]{
                                getString(R.string.title_tools),
                                getString(R.string.title_ticket),
                                getString(R.string.title_keys),
                                getString(R.string.title_archive)
                        }
                ),
                this
        );
        actionBar.setSelectedNavigationItem(1);
    }

    @Override
    public void onResume() {
        super.onResume();
        Intent intent = getIntent();
        resolveIntent(intent);
        adapter.enableForegroundDispatch(this, pendingIntent, filters,
                techLists);
    }

    @Override
    public void onStop() {
        super.onStop();
//        FileManager.saveLog(context);
    }

    @Override
    public void onNewIntent(Intent intent) {
        resolveIntent(intent);
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        // Serialize the current dropdown position.
        outState.putInt(STATE_SELECTED_NAVIGATION_ITEM,
                getActionBar().getSelectedNavigationIndex());
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.my, menu);
        console_button = menu.findItem(R.id.action_show_console);
        console_button.setIcon(R.drawable.ic_action_show_console);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_show_console) {
            showConsoleWindow();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public boolean onNavigationItemSelected(int position, long id) {
        // When the given dropdown item is selected, show its contents in the
        // container view.
        Fragment newFragment = toolsFragment;
        int enter = R.anim.fragment_slide_down;
        fm.popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE);
        switch (position) {
            case 1:
                newFragment = ticketFragment;
                enter = R.anim.fragment_slide_up;
                break;
            case 2:
                newFragment = keyList;
                enter = R.anim.fragment_slide_up;
                break;
            case 3:
                newFragment = archiveFragment;
                enter = R.anim.fragment_slide_up;
                break;
        }
        getFragmentManager().beginTransaction()
                .setCustomAnimations(enter, R.anim.fragment_slide_out)
                .replace(R.id.container, newFragment)
                .commit();

        return true;
    }

    void resolveIntent(Intent intent) {

        String action = intent.getAction();

        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)) {

            Tag tagFromIntent = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

            String timestamp = "" + Calendar.getInstance().getTime();

            Reader.history += "\nnew tag discovered on time\n" + timestamp + "\n";

            for (int k = 0; k < tagFromIntent.getTechList().length; k++) {
                if (tagFromIntent.getTechList()[k]
                        .equals("android.nfc.tech.NfcA")) {
                    vibrator.vibrate(50);
                    nfcA_available = true;
                    Reader.nfcA_card = NfcA.get(tagFromIntent);
                    if (!ticketFragment.isVisible()) {
                        toolsFragment.read(true);
                    }
                    if (!consoleWindow.isVisible()) showConsoleHint();
                    else consoleWindow.update();

                    if (ticketFragment.isVisible()) {
                        ticketFragment.setCardAvailable(true);
                    }
                }
            }
        }
    }

    @Override
    public void onAttachFragment(Fragment fragment) {
        super.onAttachFragment(fragment);

    }

    private void showConsoleWindow() {
        consoleWindow.show(fm, "console_popup");
        console_button.setIcon(R.drawable.ic_action_show_console);
    }

    private void promptNfc() {
        AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(
                this);
        alertDialogBuilder
                .setMessage(getString(R.string.nfc_disabled_msg))
                .setCancelable(false)
                .setPositiveButton(getString(R.string.action_nfc_settings),
                        new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog,
                                                int id) {
                                Intent callNFCSettingsIntent = new Intent(
                                        Settings.ACTION_NFC_SETTINGS);
                                startActivity(callNFCSettingsIntent);
                            }
                        }
                );
        alertDialogBuilder.setNegativeButton(getString(R.string.action_cancel),
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        dialog.cancel();
                    }
                }
        );
        AlertDialog alert = alertDialogBuilder.create();
        alert.show();
    }

}
