package com.example.auth.app.fragments;
/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */
import android.app.ListFragment;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.content.FileProvider;
import android.util.Log;
import android.view.ActionMode;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;
import android.widget.ProgressBar;

import com.example.auth.app.main.FileManager;
import com.example.auth.app.main.MyActivity;
import com.example.vaarajer1.auth.R;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;

public class ArchiveFragment extends ListFragment {

    public static ArchiveAdapter adapter;
    public static ArrayList<String> selected;
    private static ArrayList<String> valueList;
    private ActionMode actionMode;
    private boolean multiSelect = false;

    private View openChild;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        valueList = FileManager.getFileNames(MyActivity.outer);
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        getActivity().getActionBar().setIcon(R.drawable.ic_archive);
        getView().setBackgroundColor(getResources().getColor(R.color.background_color));

        getListView().setDivider(getResources().getDrawable(R.drawable.divider));
        getListView().setDividerHeight(2);

        Collections.reverse(valueList);

        adapter = new ArchiveAdapter(getActivity(), valueList);

        selected = new ArrayList<String>();

        setEmptyText(getString(R.string.archive_empty_hint));

        setListAdapter(adapter);

        getListView().setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {

            @Override
            public boolean onItemLongClick(AdapterView parent, View view, int position, long id) {
                if (!multiSelect) {
                    selected.add(adapter.getItem(position));
                    actionMode = getActivity().startActionMode(new ActionBarCallBack());
                }
                return true;
            }
        });

    }

    public void onListItemClick(ListView l, View v, int position, long id) {
        if (!multiSelect) {
            OpenFileTask task = new OpenFileTask();
            task.execute(adapter.getItem(position));
            openChild = v;
            toggleLoadIcon(true);
        } else {
            adapter.notifyDataSetChanged();
            if (!selected.contains(adapter.getItem(position))) {
                selected.add(adapter.getItem(position));
            } else selected.remove(adapter.getItem(position));
            actionMode.setTitle(getString(R.string.selected_msg) + selected.size());
        }
    }

    private void toggleLoadIcon(boolean load) {
        if (load) {
            openChild.findViewById(R.id.list_item_progress).setVisibility(View.VISIBLE);
            openChild.findViewById(R.id.list_item_icon).setVisibility(View.GONE);
        } else {
            openChild.findViewById(R.id.list_item_progress).setVisibility(View.GONE);
            openChild.findViewById(R.id.list_item_icon).setVisibility(View.VISIBLE);
        }
    }

    private void openItem(String data) {
        DataViewFragment dataViewFragment = new DataViewFragment();
        Bundle args = new Bundle();
        args.putString("param1", data);
        dataViewFragment.setArguments(args);
        MyActivity.fm.beginTransaction()
                .setCustomAnimations(R.anim.slide_in, R.anim.slide_out, R.anim.slide_in, R.anim.slide_out)
                .add(R.id.container, dataViewFragment).addToBackStack("").commit();
        toggleLoadIcon(false);
    }

    private class OpenFileTask extends AsyncTask<String, Long, Boolean> {
        private String data;

        @Override
        protected Boolean doInBackground(String... params) {
            data = FileManager.readFile(MyActivity.outer, params[0]);
            return true;
        }

        @Override
        protected void onPostExecute(Boolean aBoolean) {
            openItem(data);
        }

    }

    private void deleteSelected() {
        for (String item : selected) {
            if (!adapter.isEmpty()) {
                adapter.remove(item);
                MyActivity.outer.deleteFile(item);
            }
        }
        adapter.notifyDataSetChanged();
    }

    private void selectAll() {
        selected = new ArrayList<String>(valueList);
        actionMode.setTitle(getString(R.string.selected_msg) + selected.size());
        adapter.notifyDataSetChanged();
    }

    private void shareFiles() {
        ArrayList<Uri> parsed = new ArrayList<Uri>();

        Intent shareIntent = new Intent();
        shareIntent.setAction(Intent.ACTION_SEND_MULTIPLE);
        shareIntent.setType("text/plain");

        for (String fileName : selected) {
            File file = new File("data/data/com.example.vaarajer1.auth/files/" + fileName);
            if (file != null) {
                Log.d("File check", "File found, file description: " + file.toString());
                Log.d("Can read", "" + file.canRead());
            } else {
                Log.w("File check", "File not found!");
            }
            Uri fileUri = FileProvider.getUriForFile(MyActivity.outer, "com.example.vaarajer1.auth.app.fragments.ArchiveFragment", file);

            parsed.add(fileUri);
        }
        shareIntent.putExtra(android.content.Intent.EXTRA_TEXT, "exported .txt files");
        shareIntent.putParcelableArrayListExtra(Intent.EXTRA_STREAM, parsed);
        startActivity(Intent.createChooser(shareIntent, getString(R.string.share_multiple_msg)));
    }


    class ActionBarCallBack implements ActionMode.Callback {

        @Override
        public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
            switch (item.getItemId()) {
                case R.id.action_delete:
                    deleteSelected();
                    actionMode.finish();
                    break;
                case R.id.action_select_all:
                    selectAll();
                    break;
                case R.id.action_multi_share:
                    shareFiles();
                    break;
            }
            return false;
        }

        @Override
        public boolean onCreateActionMode(ActionMode mode, Menu menu) {
            getListView().setLongClickable(false);
            mode.getMenuInflater().inflate(R.menu.archive_cbar, menu);
            multiSelect = true;
            adapter.setPaintSelected(true);
            adapter.notifyDataSetChanged();
            return true;
        }

        @Override
        public void onDestroyActionMode(ActionMode mode) {
            getListView().setLongClickable(true);
            multiSelect = false;
            selected = new ArrayList<String>();
            adapter.setPaintSelected(false);
            adapter.notifyDataSetChanged();

        }

        @Override
        public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
            mode.setTitle(getString(R.string.cbar_menu_title));
            return false;
        }
    }

}