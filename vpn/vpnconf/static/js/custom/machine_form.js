$(function(){
    var new_input = $("<input>", {id: "id_project_ac", type: "text"}).insertAfter($("#id_project"))
    if ($("#id_project option:selected").html() != "---------"){
        new_input.val($("#id_project option:selected").html());
    }
    $("#id_project").css("display", "none");
    $("form").submit(function(event){
        var selected_val = $("#id_project_ac").val();
        $("#id_project option").each(function(index, elem){
            if ($(elem).html()==selected_val){
                $(elem).attr("selected", "selected");
            }
            else {
                $(elem).removeAttr("selected");
            }
        })
    });
});
    
