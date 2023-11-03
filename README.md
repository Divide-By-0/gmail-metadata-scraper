# Gmail Metadata Scraper

Log in with gmail then scrape a bunch of metadata from the emails, like the longest message id length in your inbox, or all of the selectors for all of the sending domains. Useful to populate info for zk-email and decide parameters.

If you want a config file, reach out to me.

```bash
pip3 install -r requirements.txt
python3 main.py
```

Get the env file from me and rename it to `.env`.

Then go to `127.0.0.1` in your browser. Click "Authorize" first and sign in. Then request results. It'll take a minute or two. Then click "Retrieve Domains + Selectors", and the show selectors page will show all of the domains and selectors collected in the local db form all of your past runs of the script. The "Copy All" button doesn't work, just manually copy and paste the results to me.

Thanks to [adriptech](https://replit.com/@AdripTech/gmail-Addon) for the initial repository template.
