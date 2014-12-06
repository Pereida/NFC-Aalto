package com.example.auth.app.fragments;
/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */
import android.app.DialogFragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.Switch;

import com.example.auth.app.main.MyActivity;
import com.example.auth.app.ulctools.Reader;
import com.example.vaarajer1.auth.R;

public class PrefsPopup extends DialogFragment {

    private Switch auth_switch;
    private Switch safe_mode;


    public PrefsPopup() {
        // Empty constructor required for DialogFragment
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.prefs_popup, container);

        auth_switch = (Switch) view.findViewById(R.id.auth_switch);

        auth_switch.setChecked(MyActivity.autoAuth);
        //attach a listener to check for changes in state
        auth_switch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {

            @Override
            public void onCheckedChanged(CompoundButton buttonView,
                                         boolean isChecked) {

                if (isChecked) {
                    MyActivity.autoAuth = true;
                } else {
                    MyActivity.autoAuth = false;
                }

            }
        });

        safe_mode = (Switch) view.findViewById(R.id.safeMode_switch);

        safe_mode.setChecked(Reader.safeMode
        );
        //attach a listener to check for changes in state
        safe_mode.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {

            @Override
            public void onCheckedChanged(CompoundButton buttonView,
                                         boolean isChecked) {

                ToolsFragment.toggleSafeMode();

            }
        });


        return view;
    }

}
