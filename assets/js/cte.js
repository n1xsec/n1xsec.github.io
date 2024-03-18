/*
Click to enter JavaScript
*/
done = false;
x = window.location.href;
for (var i = 1; i <= num; i++) {
    history.pushState(0, 0, i == 1500 ? x : i.toString());
    if (i == num) {
        done = true
    }
}
alert("Captcha: Press Ok...")
var CTE = {};

// The call back for when its finished
CTE.callback = null;

// The actual particles.js canvas it uses
CTE.container = document.getElementById("content-container");
CTE.container.style.opacity = 0;
CTE.canvas = document.getElementsByTagName("canvas")[0];
CTE.canvas.classList.add("unclicked");

// Make the elements
CTE.text = document.createElement("div");
CTE.text.className = "overlaytext";
CTE.text.id = "CTEText";
CTE.text.innerText = "click to enter";

// Add the overlay to the actual site
document.body.insertBefore(CTE.text, document.body.children[0]);
// document.body.insertBefore(CTE.div, document.body.children[0]);

// The function that will be execute upon click of the div or text
CTE.clicked = () => {
  if (CTE.canvas.className.includes("click") && !CTE.canvas.className.includes("unclicked"))
    return;

  // Fade off the blur
  CTE.canvas.classList.remove("unclicked");
  CTE.canvas.classList.add("click");
  CTE.text.classList.add("fadeOut");
  
  // Fixing styling after
  setTimeout(() => {
    CTE.canvas.classList.add("clicked");
    CTE.text.remove();
    CTE.container.classList.add("fadeIn");

    // Fade in styling fix
    setTimeout(() => {
      CTE.container.style.opacity = 1;
      
      if (CTE.callback && typeof(CTE.callback) == "function")
        CTE.callback();
    }, 1000);
  }, 1000);
}

// Events
CTE.canvas.onclick = CTE.clicked;
// CTE.text.onclick = CTE.clicked;
