// XSS-001: innerHTML assignment with user-controlled data
function showResult() {
    const userInput = location.hash.substring(1);
    document.getElementById('output').innerHTML = userInput;
}
