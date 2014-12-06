package com.example.auth.app.fragments;
/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */
import android.app.ActionBar;
import android.app.Fragment;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.PopupMenu;
import android.widget.TextView;
import android.widget.Toast;

import com.example.auth.app.main.FileManager;
import com.example.auth.app.main.MyActivity;
import com.example.auth.app.ulctools.Dump;
import com.example.auth.app.ulctools.Reader;
import com.example.vaarajer1.auth.R;

public class ToolsFragment extends Fragment {

    public static int card_auth0;
    public static int card_auth1;
    private static String received_data = "";
    private static TextView card_data;
    private static byte[] data = new byte[192];
    private static boolean stringAsBinary = false;
    private static ActionBar actionBar;
    private static TextView safeMode_indicator;
    private static TextView auth_info;
    private static TextView tag_hint;
    private static ImageButton btn_tools;
    private MenuItem string_switch;
    private View.OnClickListener tool_popup_listener = new View.OnClickListener() {
        public void onClick(View v) {
            tool_popup();
        }
    };

    public ToolsFragment() {
        // Required empty public constructor
    }

    public static void update() {
        if (MyActivity.nfcA_available) ToolsFragment.read(false);
    }

    public static void toggleSafeMode() {
        Reader.safeMode = !Reader.safeMode;
        if (Reader.safeMode) {
            safeMode_indicator.setEnabled(true);
            safeMode_indicator.setText("safe mode on");
        } else {
            safeMode_indicator.setEnabled(false);
            safeMode_indicator.setText("safe mode off");
        }
    }

    public static void read(boolean display) {
        boolean autoAuth = MyActivity.autoAuth;
        if (MyActivity.nfcA_available) {
            String info = "";
            if (Reader.connect()) {
                Reader.readMemory(data, autoAuth, display);
                Reader.disconnect();
                int mode = 0;
                if (stringAsBinary) mode = 1;
                received_data = Dump.hexView(data, mode);
                card_data.setText(received_data);
                card_auth0 = (int) data[42 * 4];
                card_auth1 = (int) data[43 * 4];
                if (card_auth0 > 2 && card_auth0 <= 48) {
                    if (card_auth1 == 1) info += "write protected starting from page " + card_auth0;
                    else if (card_auth1 == 0)
                        info += "R/W protected starting from page " + card_auth0;
                }
                auth_info.setText(info);
                auth_info.setEllipsize(TextUtils.TruncateAt.MARQUEE);
                auth_info.setSelected(true);
                tag_hint.setVisibility(View.GONE);
            }
        }
    }

    public static void erase() {
        ErasePopup erasePopup = new ErasePopup();
        erasePopup.show(MyActivity.fm, "erase_popup");
    }

    public static void write(String content, int page, boolean auth) {
        byte[] data = new byte[4];
        if (content.regionMatches(0, "0x", 0, 2)) {
            for (int i = 0; i < 4; i++) {
                data[i] = (byte) Integer.parseInt("" + content.charAt(i + 2));
            }
        } else data = content.getBytes();
        Log.d("Write", "Data length: " + data.length);
        Reader.connect();
        Reader.updatePage(data, page, auth);
        MyActivity.showConsoleHint();
        Reader.disconnect();
        update();
    }

    public static void addToArchive() {
        String UID;
        byte[] uid_data = new byte[8];
        System.arraycopy(data, 0, uid_data, 0, 8);
        UID = Dump.hex(uid_data, stringAsBinary).toUpperCase();
        received_data = Dump.hexView(data, 2);
        FileManager.saveDataAsTxt(MyActivity.outer, received_data, UID);
        Toast.makeText(MyActivity.outer, "Data saved", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        setHasOptionsMenu(true);
        super.onCreate(savedInstanceState);

    }

    @Override
    public void onDetach() {
        super.onDetach();
    }

    @Override
    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        inflater.inflate(R.menu.fragment_tools, menu);

        string_switch = menu.findItem(R.id.action_switch_view);
        if (stringAsBinary) string_switch.setTitle("BIN");
        else string_switch.setTitle("HEX");
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_switch_view) {
            switchStringView();
            return true;
        }
        if (id == R.id.action_refresh) {
            update();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        actionBar = getActivity().getActionBar();

        actionBar.setIcon(R.drawable.ic_launcher);
        View v = inflater.inflate(R.layout.fragment_tools, container, false);

        safeMode_indicator = (TextView) v.findViewById(R.id.safemode_indicator);
        auth_info = (TextView) v.findViewById(R.id.auth_info);

        if (Reader.safeMode) {
            safeMode_indicator.setEnabled(true);
            safeMode_indicator.setText("safe mode on");
        } else {
            safeMode_indicator.setEnabled(false);
            safeMode_indicator.setText("safe mode off");
        }

        card_data = (TextView) v.findViewById(R.id.tools_data_view);
        card_data.setText(received_data);

        btn_tools = (ImageButton) v.findViewById(R.id.tool_list);
        btn_tools.setOnClickListener(tool_popup_listener);

        tag_hint = (TextView) v.findViewById(R.id.tag_hint);
        if (card_data.getText().length() > 5) tag_hint.setVisibility(View.GONE);

        if (MyActivity.nfcA_available) {
            btn_tools.setEnabled(true);
        }

        return v;
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
    }

    private void changeKeyOnCard() {
        AuthKeyPopup authenticationWindow = AuthKeyPopup.newInstance(0);
        authenticationWindow.show(MyActivity.fm, "key_popup");
    }

    private void tool_popup() {
        PopupMenu pum = new PopupMenu(getActivity(), getActivity().findViewById(R.id.tool_list));
        pum.inflate(R.menu.popup_menu);
        if (MyActivity.nfcA_available) {
            pum.getMenu().getItem(0).setEnabled(true);
            pum.getMenu().getItem(1).setEnabled(true);
            pum.getMenu().getItem(2).setEnabled(true);
            pum.getMenu().getItem(3).setEnabled(true);
            pum.getMenu().getItem(4).setEnabled(true);
            pum.getMenu().getItem(5).setEnabled(true);
        } else {
            pum.getMenu().getItem(0).setEnabled(false);
            pum.getMenu().getItem(1).setEnabled(false);
            pum.getMenu().getItem(2).setEnabled(false);
            pum.getMenu().getItem(3).setEnabled(false);
            pum.getMenu().getItem(4).setEnabled(false);
            pum.getMenu().getItem(5).setEnabled(false);
        }
        if (received_data.length() == 0) {
            pum.getMenu().getItem(7).setEnabled(false);
        }
        pum.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                switch (item.getItemId()) {
                    case R.id.action_erase:
                        erase();
                        break;
                    case R.id.action_set_auth0:
                        setAuth(0);
                        break;
                    case R.id.action_set_auth1:
                        setAuth(1);
                        break;
                    case R.id.action_auth_test:
                        Reader.testAuthenticate();
                        break;
                    case R.id.action_write:
                        showWritePopup();
                        break;
                    case R.id.action_preferences:
                        showPrefs();
                        break;
                    case R.id.action_write_key:
                        changeKeyOnCard();
                        break;
                    case R.id.action_archive:
                        addToArchive();
                    default:
                        break;
                }
                return false;

            }
        });
        pum.show();

    }

    private void setAuth(int auth) {
        SetAuthPopup authPopup = SetAuthPopup.newInstance(auth);
        authPopup.show(MyActivity.fm, "auth_popup");
    }

    private void showWritePopup() {
        WritePopup writePopup = new WritePopup();
        writePopup.show(MyActivity.fm, "write_popup");
    }

    private void showPrefs() {
        PrefsPopup prefsPopup = new PrefsPopup();
        prefsPopup.show(MyActivity.fm, "prefs_popup");
    }

    private void switchStringView() {
        stringAsBinary = !stringAsBinary;
        if (stringAsBinary) {
            string_switch.setTitle("BIN");
            received_data = Dump.hexView(data, 1);
            card_data.setText(received_data);
            btn_tools.setAlpha(150);
        } else {
            string_switch.setTitle("HEX");
            received_data = Dump.hexView(data, 0);
            card_data.setText(received_data);
            btn_tools.setAlpha(255);
        }
        if (card_data.getText().length() > 5) tag_hint.setVisibility(View.GONE);
    }
}
