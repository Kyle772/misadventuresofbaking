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
    
    // https://css-tricks.com/snippets/jquery/horz-scroll-with-mouse-wheel/
    $(function() {
       $("#BlogFileSel").mousewheel(function(event, delta) {
          this.scrollLeft -= 30 * delta;
          event.preventDefault();
       });
    });

    // File con hover ui
    $(".file-con .item").hover(function () {
        var ele = $(this).children(".button-con");
        ele.toggleClass("visible");
    });
    
    // File con /mainassign FOR BLOG ADDING NOT UPLOAD PAGE
    // handless success/fail classes after post
    $(".file-con .item div[data-mainassignblog]").click(function () {
        var link;
        $this = $(this);
        link = $this.attr("data-mainassignblog");
        $("#mainImage").attr("value", link);
    });
    
    // File con /mainassign 
    // handless success/fail classes after post
    $(".file-con .item div[data-mainassign]").click(function () {
        var $this = $(this);
        $.post($(this).attr("data-mainassign"), function () {
            console.log("Assigning main image");
        }).done(function () {
            $this.parent().siblings(".status").each(function () {
                var link = $this.parent().parent().attr("href");
                $(this).addClass("success");
                $("#Dashboard").attr("data-backimg", link)
            });
        }).fail(function () {
            $this.parent().siblings(".status").each(function () {
                $(this).addClass("fail");
            });
        }).always(function () {
            setTimeout(function () {
                $this.parent().siblings(".status").each(function () {
                    $(this).removeClass("fail").removeClass("success");
                });
            }, 800);
        });
    });
    
    // File con /delete 
    // handles success/fail classes after post
    $(".file-con .item div[data-deleteurl]").click(function () {
        var $this = $(this);
        var succ = false;
        $.post($(this).attr("data-deleteurl"), function () {
            console.log("Deleting image");
        }).done(function () {
            $this.parent().siblings(".status").each(function () {
                succ = true;
                $(this).addClass("success");
            });
        }).fail(function () {
            $this.parent().siblings(".status").each(function () {
                $(this).addClass("fail");
            });
        }).always(function () {
            // Remove animated statuses
            setTimeout(function () {
                $this.parent().siblings(".status").each(function () {
                    $(this).removeClass("fail").removeClass("success");
                });
            }, 800);
            // Delete element from page
            setTimeout(function () {
                if (succ) {
                    $this.parent().siblings(".status").each(function () {
                        $(this).parent().remove();
                    });
                }
            }, 800);
        });
    });

    $("div[data-clipboard]").on("click", function () {
        toClipboard($(this));
        var $this = $(this);
        $this.parent().siblings(".status").each(function () {
            $(this).addClass("clip");
        });
        // Remove animated statuses
        setTimeout(function () {
            $this.parent().siblings(".status").each(function () {
                $(this).removeClass("clip");
            });
        }, 800);
    });
});