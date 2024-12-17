import openai

# Replace 'your_openai_api_key' with your OpenAI API key
openai.api_key = "sk-bnOUc36c-ydGOCa0BFX4cw"

def roast_person(name, traits=None):
    """
    Generate a roast for a specific person using OpenAI GPT.
    
    :param name: The name of the person to roast.
    :param traits: Optional personality traits or context for the roast.
    :return: A generated roast string.
    """
    prompt = f"Roast {name} with humor. Keep it light and funny."
    if traits:
        prompt += f" This person is known for {', '.join(traits)}."

    try:
        response = openai.Completion.create(
            engine="text-davinci-003",  # You can use a different model, such as gpt-4 if available
            prompt=prompt,
            max_tokens=100,
            temperature=0.7
        )
        return response.choices[0].text.strip()
    except Exception as e:
        return f"An error occurred: {e}"

# Example usage
if __name__ == "__main__":
    name = "John"
    traits = ["being late", "loud laughter"]
    roast = roast_person(name, traits)
    print(f"Roast for {name}: {roast}")
