$(document).ready( function() {
    if ($(".blog-con > .content").width > 850) {
        $(".recipe-con > .recipe").removeClass("hidden");
    } else {
        $(".recipe-con > .recipe").addClass("hidden");
    }
    
    $("#RecipeBut").on("click", function () {
        $(".recipe-con > .recipe").removeClass("hidden");
    });
    
})