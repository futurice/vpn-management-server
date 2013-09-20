function setupFirewallApp(){
    $("input[name='machine_security']").click(function(){
        manageLockedFields(this);
    });
    var checked_security = $("input[name='machine_security']:checked")[0];
    manageLockedFields(checked_security);
}

function manageLockedFields(elem){
    //Handler for disabling the fields for opening ports, depending on machine_security's value.
    var security = $(elem).val();
    if (security == "public"){
        $("input").removeAttr("disabled");
        $("input[value='fully_open']").parent().removeClass("disabled");
    }
    else if (security == "protected"){
        $("input").removeAttr("disabled");
        $("input[value='fully_open']").parent().removeClass("disabled");
    }
    else if (security == "confidential"){
        $("input[value='fully_open']:checked").each(function(index, found){
            $("input[name="+$(found).attr("name")+"][value='not_open']").attr({checked: "checked"});
        });
        $("input[value='fully_open']").attr({disabled: "disabled"});
        $("input[value='fully_open']").parent().addClass("disabled");
    }    
}

$(document).ready(setupFirewallApp);

function setupHelpText(elems){
    //Handler for setting style and help text on a rule input.
    var inputs = elems.find("input");
    inputs.addClass("disabled");
    inputs.DefaultValue("default-value", "x.x.x.x/x or x.x.x.x");
    inputs.focus(function(event){
        $(this).removeClass("disabled");
    });
    inputs.blur(function(event){
        if ($(this).val() == ""){
            $(this).addClass("disabled");
        }
    });
}
