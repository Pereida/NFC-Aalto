package com.example.auth.app.fragments;
/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */
import android.app.Fragment;
import android.media.AudioManager;
import android.media.ToneGenerator;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import com.example.auth.app.main.MyActivity;
import com.example.auth.ticket.Ticket;
import com.example.vaarajer1.auth.R;

import java.security.GeneralSecurityException;

public class EmulatorFragment extends Fragment {

    private static Ticket ticket;

    private static TextView ticket_info;

    public EmulatorFragment() {
        try {
            ticket = new Ticket();
        } catch (GeneralSecurityException g) {
            Toast.makeText(MyActivity.outer, "Error with TicketMac", Toast.LENGTH_LONG).show();
        }
    }

    public void use() {
        boolean result = TicketFragment.use();
        if (result) {
            ToneGenerator toneG = new ToneGenerator(AudioManager.STREAM_RING, 100);
            toneG.startTone(ToneGenerator.TONE_CDMA_ALERT_CALL_GUARD, 100);
        } else {
            ToneGenerator toneG = new ToneGenerator(AudioManager.STREAM_RING, 100);
            toneG.startTone(ToneGenerator.TONE_CDMA_ABBR_INTERCEPT, 100);
        }
        ticket_info.setText(ticket.infoToShow);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }


    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View v = inflater.inflate(R.layout.fragment_emulator, container, false);
        getActivity().getActionBar().setIcon(R.drawable.ic_launcher);

        ticket_info = (TextView) v.findViewById(R.id.ticket_info);
        ticket_info.setText("Ticket info");

        return v;
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
    }


}
