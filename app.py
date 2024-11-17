import streamlit as st
from datasets import load_dataset

# Load the CounselChat dataset
ds = load_dataset("nbertagnolli/counsel-chat")

# Streamlit App
st.title("CounselChat App")
st.write("This app provides counseling advice based on user input.")

# User input: a question or description
user_input = st.text_input("Enter your question or issue:")

# Display a response if user enters something
if user_input:
    st.write("Searching for relevant advice...")

    # Simple example: search for questions that match the user input
    # This can be enhanced with NLP models for better matching
    responses = []
    for example in ds['train']:
        if user_input.lower() in example['question'].lower():
            responses.append(example['answer'])
    
    if responses:
        st.write("Here are some relevant answers:")
        for i, response in enumerate(responses[:3]):  # Limit to top 3 responses
            st.write(f"{i+1}. {response}")
    else:
        st.write("Sorry, no relevant advice found.")
 
