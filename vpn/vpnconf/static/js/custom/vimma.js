jQuery.fn.log = function (msg) {
  console.log("%s: %o", msg, this);
  return this;
};


function toggleSection(selector) {
	$(selector).toggle();
}

$(function() {
    $(".display-none").hide();
});
