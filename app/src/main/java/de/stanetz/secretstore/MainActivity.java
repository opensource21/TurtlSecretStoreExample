package de.stanetz.secretstore;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;

import com.lyonbros.turtlstore.SecurityStore;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        final RadioGroup secureMethodGroup = findViewById(R.id.securityModeGroup);
        if (secureMethodGroup.getCheckedRadioButtonId() == -1) {
            ((RadioButton) findViewById(R.id.noneRBtn)).setChecked(true);
        }
        secureMethodGroup.setVisibility(View.GONE);
        handleInput();
        handleOutput();

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });
    }

    private void handleOutput() {
        final TextView output = findViewById(R.id.output);
        final Button loadBtn = findViewById(R.id.loadBtn);
        loadBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View button) {
                final SecurityStore store = new SecurityStore(MainActivity.this);
                final byte[] loadedText = store.loadKey();
                if (loadedText == null) {
                    output.setText("");
                } else {
                    output.setText(new String(loadedText));
                }
            }
        });

    }

    private void handleInput() {
        final RadioGroup secureMethodGroup = findViewById(R.id.securityModeGroup);
        final EditText input = findViewById(R.id.inputText);
        final Button saveBtn = findViewById(R.id.safeBtn);
        saveBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View button) {
                final SecurityStore store = new SecurityStore(MainActivity.this);
                final Button radioButton = findViewById(secureMethodGroup.getCheckedRadioButtonId());
                store.storeKey(input.getText().toString().getBytes());
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
