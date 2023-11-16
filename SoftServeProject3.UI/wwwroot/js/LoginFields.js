window.moveFocus = function () {
    var ele = document.activeElement;
    var tabIndex = ele.tabIndex;
    var inputs = document.getElementById("my-form").elements;
    for (i = 0; i < inputs.length; i++) {
        if (inputs[i].tabIndex > tabIndex) {
            inputs[i].focus();
            return;
        }
    }
};