async function analyze() {
    const response = await fetch("http://127.0.0.1:8000/analyze");
    const data = await response.json();

    document.getElementById("output").innerText =
        JSON.stringify(data, null, 2);
}