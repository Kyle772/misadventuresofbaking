/*jslint es5: true */


$(document).ready(function () {
    function backImg(clss) {
        $(clss).each(function () {
            var attr = $(this).attr('data-backimg');

            if (typeof attr !== typeof undefined && attr !== false) {
                $(this).css('background-image', 'url(' + attr + ')');
            }
        });
    }
    
    $(function () {
        $('#fileUpload').fileupload({
            dataType: 'json',
            url: '/dashboard/file',
            sequentialUploads: true,
            maxFileSize: 8000000,
            done: function (e, data) {
                $.each(data.result.files, function (index, file) {
                    $('<p/>').text(file.name).appendTo(document.body);
                });
            }
        });

        $('#fileUpload').fileupload({
            dataType: 'json',
            url: "/dashboard/file/add",
            add: function (e, data) {
                data.context = $('<p/>').text('Uploading...').replaceAll($("#FileUploadForm .status"));
                data.submit();
            },
            maxFileSize: 8000000,
            done: function (e, data) {
                console.log(data.result);
                data.context.text('Upload finished.');
                $(".content > .file-con > .upload-con").prepend('\
                    <div class="item">\
                        <div class="img" data-backimg="' + (data.result.files["0"].url) + '"></div>\
                        <div class="info">\
                            <p>Uploader: ' + data.result.files["0"].user + '</p>\
                            <p>Filename: ' + data.result.files["0"].name + '</p>\
                            <p>Filesize: ' + data.result.files["0"].size + ' Bytes</p>\
                            <p>URL: <a href="' + data.result.files["0"].url + '">Link!</a></p>\
                        </div>\
                    </div>\
                ');
                if (data.result.files["0"].error != undefined) {
                    $(".content > .upload-con .info:last").append('\
                        <p class="error">Error: ' + data.result.files["0"].error + '</p>\
                    ');    
                }
                backImg('.item > div');
                var info = data.result.files["0"];
                info = JSON.stringify(info);
                console.log(info);
                $.ajax({
                    type: "post",
                    url: "/dashboard/file/img/add",
                    data: info,
                    dataType: 'json',
                    done: function (e, data) {
                        console.log(e);
                    }
                });
            }
        });
    });
});