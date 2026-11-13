import streamlit as st
import envfile
envfile.load()
import dashboard_auth as auth
from oracle_intelligence.ui import render

st.set_page_config(page_title="Oracle Intelligence", page_icon="*)", layout="wide")
render(st, auth)
