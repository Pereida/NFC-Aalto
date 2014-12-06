package com.example.auth.app.fragments;
/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */
import android.app.Fragment;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.example.auth.app.main.MyActivity;
import com.example.auth.app.ulctools.Reader;
import com.example.auth.ticket.Ticket;
import com.example.vaarajer1.auth.R;

import java.security.GeneralSecurityException;
import java.util.Date;

public class TicketFragment extends Fragment {

    public static TextView ticket_dump;
    private static boolean nfcA_available = false;
    private static TextView tag_hint;
    public static boolean hide_hint = false;
    private Button btn_format;
    private Button btn_issue;
    private Button btn_use;
    private Button btn_test_use;
    private EmulatorFragment emulatorFragment;

    private static Ticket ticket;

    public TicketFragment() {
        try {
            ticket = new Ticket();
        } catch (GeneralSecurityException g) {
            Toast.makeText(MyActivity.outer, "Error with TicketMac", Toast.LENGTH_LONG).show();
        }
    }

    private View.OnClickListener test_use_listener = new View.OnClickListener() {
        public void onClick(View v) {
            showEmulator();
        }
    };
    private View.OnClickListener format_listener = new View.OnClickListener() {
        public void onClick(View v) {
            if (Reader.connect()) {
                boolean status = ticket.format();
                if (status) {
                    String info = "Format successful";
                    Toast.makeText(MyActivity.outer, info, Toast.LENGTH_SHORT).show();
                    System.out.println(info);
                    Reader.history += "\n" + info + "\n--------------------------------";
                }
                ticket.dump();
                Reader.disconnect();
            }
        }
    };
    private View.OnClickListener issue_listener = new View.OnClickListener() {
        public void onClick(View v) {
            if (Reader.connect()) {
                try {
                    int days = 30;
                    int uses = 10;
                    String msg = "Issuing new ticket for " + days + " days, "
                            + uses + " uses...";
                    System.out.println(msg);
                    Reader.history += "\n" + msg + "\n";
                    // Time expressed as MINUTES since January 1, 1970.
                    int currentTime = (int) ((new Date()).getTime() / 1000 / 60);
                    int expiryTime = currentTime + days * 24 * 60;
                    String info = "\nCurrent time: "
                            + new Date((long) currentTime * 60 * 1000) + "\nExpiry time: "
                            + new Date((long) expiryTime * 60 * 1000) + "\nRemaining uses: " + uses;
                    System.out.println(info);
                    Reader.history += "\n" + info + "\n--------------------------------";

                    // You need to implement this method:
                    boolean status = ticket.issue(expiryTime, uses);
                    if (status)
                        msg = "Ticket issuing successful";
                    else
                        msg = "Ticket issuing failed";
                    Toast.makeText(MyActivity.outer, msg, Toast.LENGTH_SHORT).show();
                    System.out.println(msg);
                    Reader.history += "\n" + msg + "\n--------------------------------";
                } catch (GeneralSecurityException g) {
                    Log.d("Error", g.toString());
                }
                ticket.dump();
                Reader.disconnect();
            }
        }
    };
    private View.OnClickListener use_listener = new View.OnClickListener() {
        public void onClick(View v) {
            use();
        }
    };

    public static boolean use() {
        if (Reader.connect()) {
            try {
                int currentTime = (int) ((new Date()).getTime() / 1000 / 60);
                // You need to implement these methods:
                ticket.use(currentTime);
                ticket.dump();
                Reader.disconnect();
                boolean valid = ticket.isValid();
                int uses = ticket.getRemainingUses();
                int expiryTime = ticket.getExpiryTime();
                String msg;

                if (valid) {
                    msg = "Used ticket successfully. The ticket was valid.";
                } else {
                    msg = "Ticket use FAILED. The following data may be INVALID.";
                }
                System.out.println(msg);
                Reader.history += "\n" + msg + "\n";
                Toast.makeText(MyActivity.outer, msg, Toast.LENGTH_SHORT).show();

                String info = "\nCurrent time: "
                        + new Date((long) currentTime * 60 * 1000) + "\nExpiry time: "
                        + new Date((long) expiryTime * 60 * 1000) + "\nRemaining uses: " + uses;
                System.out.println(info);
                Reader.history += "\n" + info + "\n--------------------------------";
                return valid;
            } catch (GeneralSecurityException g) {
                Log.d("Error", g.toString());
                return false;
            }
        } else return false;
    }

    public void setCardAvailable(boolean b) {
        nfcA_available = b;
        btn_format.setEnabled(b);
        btn_issue.setEnabled(b);
        btn_use.setEnabled(b);
        btn_test_use.setEnabled(b);
        if (!emulatorFragment.isVisible()) {
            if (Reader.connect()) {
            	Ticket.isAuthenticated = false;
                ticket.dump();
                tag_hint.setVisibility(View.GONE);
                Reader.disconnect();
            }
        } else {
            emulatorFragment.use();
            tag_hint.setVisibility(View.GONE);
        }
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View v = inflater.inflate(R.layout.fragment_ticket, container, false);
        getActivity().getActionBar().setIcon(R.drawable.ic_launcher);
        emulatorFragment = new EmulatorFragment();

        ticket_dump = (TextView) v.findViewById(R.id.ticket_dump);

        btn_format = (Button) v.findViewById(R.id.ticket_btn_format);
        btn_issue = (Button) v.findViewById(R.id.ticket_btn_issue);
        btn_use = (Button) v.findViewById(R.id.ticket_btn_use);
        btn_test_use = (Button) v.findViewById(R.id.ticket_btn_test_use);

        tag_hint = (TextView) v.findViewById(R.id.tag_hint);

        btn_format.setOnClickListener(format_listener);
        btn_issue.setOnClickListener(issue_listener);
        btn_use.setOnClickListener(use_listener);
        btn_test_use.setOnClickListener(test_use_listener);

        if (nfcA_available) {
            btn_format.setEnabled(true);
            btn_issue.setEnabled(true);
            btn_use.setEnabled(true);
        } else {
            btn_format.setEnabled(false);
            btn_issue.setEnabled(false);
            btn_use.setEnabled(false);
        }
        if (ticket_dump.getText().length() > 5) tag_hint.setVisibility(View.GONE);

        // Always enable safemode
        Reader.safeMode = true;


        return v;
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
    }

    public void showEmulator() {
        if (!emulatorFragment.isVisible()) {
            MyActivity.fm.beginTransaction()
                    .setCustomAnimations(R.anim.slide_in, R.anim.slide_out, R.anim.slide_in, R.anim.slide_out)
                    .add(R.id.container, emulatorFragment).addToBackStack("").commit();
        } else {
            MyActivity.fm.popBackStack();
        }
    }


}
