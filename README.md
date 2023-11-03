# Gmail Metadata Scraper

Log in with gmail then scrape a bunch of metadata from the emails, like the longest message id length in your inbox, or all of the selectors for all of the sending domains. Useful to populate info for zk-email and decide parameters.

If you want a config file, reach out to me.

```bash
pip3 install -r requirements.txt
python3 main.py
```

Get the env file from me and rename it to `.env`.

Then sign in, and request results. It'll take a minute or two. Then the show selectors page will continually collect all your selectors in a local db. It has a copy all that doesn't work, just manually copy and paste it to me.

Thanks to [adriptech](https://replit.com/@AdripTech/gmail-Addon) for the initial repository template.
