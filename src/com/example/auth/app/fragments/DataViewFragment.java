package com.example.auth.app.fragments;
/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */
import android.app.Fragment;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ShareActionProvider;
import android.widget.TextView;

import com.example.vaarajer1.auth.R;

public class DataViewFragment extends Fragment {

    private static ShareActionProvider shareActionProvider;

    private static String content;

    private TextView data_view;

    public DataViewFragment() {
        // Required empty public constructor
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
        if (getArguments() != null) {
            content = getArguments().getString("param1");
        }
    }

    @Override
    public void onPrepareOptionsMenu(Menu menu) {
        super.onPrepareOptionsMenu(menu);
        MenuItem menuShare = menu.findItem(R.id.action_share);
        shareActionProvider = (ShareActionProvider) menuShare.getActionProvider();
        shareActionProvider.setShareIntent(createShareIntent());
    }

    protected Intent createShareIntent() {
        Intent shareIntent = new Intent(Intent.ACTION_SEND);
        shareIntent.setType("text/plain");
        shareIntent.putExtra(android.content.Intent.EXTRA_SUBJECT, "Card data");
        shareIntent.putExtra(android.content.Intent.EXTRA_TEXT, content);
        return shareIntent;
    }

    @Override
    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        inflater.inflate(R.menu.fragment_data_view, menu);

    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View view = inflater.inflate(R.layout.fragment_data_view, container, false);

        data_view = (TextView) view.findViewById(R.id.file_data_view);
        data_view.setText(content);

        return view;
    }

}
