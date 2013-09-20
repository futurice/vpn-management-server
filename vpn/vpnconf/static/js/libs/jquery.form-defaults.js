(function($) {
String.prototype.trim = function() {
return this.replace(/^\s+|\s+$/g,"");
}
$.fn.DefaultValue = function(klass,text) {
return this.each(function() {
//Make sure we're dealing with text-based form fields
if (this.type != 'text' && this.type != 'password' && this.type != 'textarea') {
return;
}

//Store field reference
var fld_current = this;
var fldVal = this.value.toLowerCase().trim();
var textVal = text.toLowerCase().trim();

//Set value initially if none are specified
if (fldVal == textVal || fldVal == "") {
$(this).addClass(klass);
this.value = text;
}

//Remove values on focus
$(this).focus(function() {
var fldVal = this.value.toLowerCase().trim();
if (fldVal == textVal || fldVal == "") {
this.value = "";
$(this).removeClass(klass);
}
});

//Place values back on blur
$(this).blur(function() {
var fldVal = this.value.toLowerCase().trim();
if (fldVal == textVal || fldVal == "") {
$(this).addClass(klass);
this.value = text;
}
});

//Capture parent form submission
//Remove field values that are still default
$(this).parents("form").each(function() {
//Bind parent form submit
$(this).submit(function() {
if (fld_current.value.toLowerCase().trim() == textVal) {
fld_current.value = "";
}
});
});
});
};
})(jQuery);
