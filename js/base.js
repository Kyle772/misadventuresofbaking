$(document).ready(function () {   
    function toClipboard(jElement) {
        var temp = $("<input>");
        $("body").append(temp);
        console.log("Appended");
        temp.val(jElement.attr("data-clipboard")).select();
        console.log("assigned text");
        document.execCommand("copy");
        console.log("copied");
        temp.remove();
        console.log("removed");
    }
    
    function backimg(clss) {
        $(clss).each(function () {
            var attr = $(this).attr('data-backimg'),
                attrShaded = $(this).attr('data-shaded');
            
            if (typeof attr !== typeof undefined && attr !== false) {
                if (attrShaded) {
                    $(this).css('background-image', ' -webkit-linear-gradient(315deg, rgba(30, 33, 33, .82) 1%, rgba(32, 32, 32, .14) 98%), linear-gradient(135deg, rgba(30, 33, 33, .82) 1%, rgba(32, 32, 32, .14) 98%), url(' + attr + ')');
                } else {
                    $(this).css('background-image', 'url(' + attr + ')');
                }
            }
        });
    }
    
    function txtCol(clss) {
        $(clss).each(function () {
            var attr = $(this).attr('data-backcol');

            if (typeof attr !== typeof undefined && attr !== false) {
                $(this).css('background-color', attr);
            }
        });
    }
    
    /* Begin */

    backimg('div[data-backimg]');

    $("div[data-clipboard]").on("click", function () {
        toClipboard($(this));
    });
});