package com.example.auth.app.fragments;
/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */
import android.app.DialogFragment;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.ImageButton;
import android.widget.NumberPicker;
import android.widget.Switch;

import com.example.auth.app.main.MyActivity;
import com.example.auth.app.ulctools.Reader;
import com.example.vaarajer1.auth.R;

public class SetAuthPopup extends DialogFragment {

    private static boolean auth1;
    private static int mode;

    private String auth0Info = MyActivity.outer.getString(R.string.auth0_info);

    private View.OnClickListener btn_auth_set_listener = new View.OnClickListener() {
        public void onClick(View v) {
            if (mode == 0) {
                if (Reader.connect()) {
                    ;
                    Reader.setAuth0(picker1.getValue(), true);
                    Reader.disconnect();
                    ToolsFragment.update();
                }
            } else {
                if (Reader.connect()) {
                    Reader.setAuth1(auth1, true);
                    Reader.disconnect();
                    ToolsFragment.update();
                }
            }
            dismiss();
        }
    };
    private Button btn_auth_set;
    private Button btn_auth_cancel;
    private ImageButton info_popup;

    private NumberPicker picker1;

    private Switch auth1_switch;


    private View.OnClickListener btn_auth_cancel_listener = new View.OnClickListener() {
        public void onClick(View v) {
            dismiss();
        }
    };

    public SetAuthPopup() {
        // Empty constructor required for DialogFragment
    }

    private static void setMode(int arg) {
        mode = arg;
    }

    public static SetAuthPopup newInstance(int arg) {
        SetAuthPopup w = new SetAuthPopup();
        w.setMode(arg);
        return w;
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view;

        if (mode == 0) {
            view = inflater.inflate(R.layout.auth_popup_0, container);

            picker1 = (NumberPicker) view.findViewById(R.id.picker1);
            picker1.setMaxValue(48);
            picker1.setMinValue(3);
            picker1.setValue(ToolsFragment.card_auth0);
            picker1.setWrapSelectorWheel(true);
            picker1.setOnValueChangedListener(new NumberPicker.
                    OnValueChangeListener() {
                @Override
                public void onValueChange(NumberPicker picker, int
                        oldVal, int newVal) {
                    picker1.setValue(newVal);
                }
            });

            info_popup = (ImageButton) view.findViewById(R.id.info_popup);
            info_popup.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    InfoPopup infoPopup = new InfoPopup();
                    infoPopup.setInfoText(auth0Info);
                    infoPopup.show(MyActivity.fm, "info_popup");
                }
            });

        } else {
            view = inflater.inflate(R.layout.auth_popup_1, container);

            auth1_switch = (Switch) view.findViewById(R.id.auth1);
            Log.d("Auth1", "" + ToolsFragment.card_auth1);

            if (ToolsFragment.card_auth1 == 1) {
                Log.d("Auth1", "match");
                auth1 = false;
            } else auth1 = true;
            auth1_switch.setChecked(auth1);

            //attach a listener to check for changes in state
            auth1_switch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {

                @Override
                public void onCheckedChanged(CompoundButton buttonView,
                                             boolean isChecked) {

                    auth1 = isChecked;

                }
            });
        }

        btn_auth_set = (Button) view.findViewById(R.id.btn_auth_set);
        btn_auth_cancel = (Button) view.findViewById(R.id.btn_auth_cancel);

        btn_auth_set.setOnClickListener(btn_auth_set_listener);
        btn_auth_cancel.setOnClickListener(btn_auth_cancel_listener);

        return view;
    }

}
