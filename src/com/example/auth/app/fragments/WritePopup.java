package com.example.auth.app.fragments;
/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */
import android.app.DialogFragment;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.NumberPicker;
import android.widget.TextView;

import com.example.auth.app.ulctools.Reader;
import com.example.vaarajer1.auth.R;

public class WritePopup extends DialogFragment {

    private Button btn_write;
    private Button btn_write_cancel;
    private EditText contentEdit;
    private NumberPicker page_picker;
    private CheckBox checkBox_write_auth;
    private TextView current_key;

    private boolean write_auth = false;

    private View.OnClickListener btn_write_listener = new View.OnClickListener() {
        public void onClick(View v) {
            ToolsFragment.write("" + contentEdit.getText(), page_picker.getValue(), write_auth);
            dismiss();
        }
    };
    private View.OnClickListener btn_write_cancel_listener = new View.OnClickListener() {
        public void onClick(View v) {
            dismiss();
        }
    };

    public WritePopup() {
        // Empty constructor required for DialogFragment
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.write_popup, container);

        btn_write = (Button) view.findViewById(R.id.btn_write);
        btn_write_cancel = (Button) view.findViewById(R.id.btn_write_cancel);
        contentEdit = (EditText) view.findViewById(R.id.content_edit);
        page_picker = (NumberPicker) view.findViewById(R.id.page_picker);

        page_picker = (NumberPicker) view.findViewById(R.id.page_picker);
        page_picker.setMaxValue(39);
        page_picker.setMinValue(4);
        page_picker.setWrapSelectorWheel(true);
        page_picker.setOnValueChangedListener(new NumberPicker.
                OnValueChangeListener() {
            @Override
            public void onValueChange(NumberPicker picker, int
                    oldVal, int newVal) {
                page_picker.setValue(newVal);
            }
        });

        current_key = (TextView) view.findViewById(R.id.current_auth_key);

        checkBox_write_auth = (CheckBox) view.findViewById(R.id.check_box_write_auth);
        checkBox_write_auth.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                if (((CheckBox) v).isChecked()) {
                    current_key.setText(getString(R.string.key_in_use) + Reader.authKey);
                    current_key.setAlpha(255);
                    write_auth = true;
                } else {
                    write_auth = false;
                    current_key.setAlpha(0);
                }

            }
        });
        btn_write.setEnabled(false);

        contentEdit.addTextChangedListener(new TextWatcher() {
            @Override
            public void afterTextChanged(Editable arg0) {
            }

            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (contentEdit.getText().toString().length() == 4) {
                    btn_write.setEnabled(true);
                } else if (contentEdit.getText().toString().regionMatches(0, "0x", 0, 2) && contentEdit.getText().toString().length() == 6) {
                    btn_write.setEnabled(true);
                } else btn_write.setEnabled(false);
            }
        });


        btn_write.setOnClickListener(btn_write_listener);
        btn_write_cancel.setOnClickListener(btn_write_cancel_listener);

        return view;
    }

}
