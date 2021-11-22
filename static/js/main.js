$(document).ready(function () {
  $(".nav-tabs a").click(function () {
    $(this).tab("show");
  });
});

$(".custom-file-input").on("change", function () {
  var fileName = $(this).val().split("\\").pop();
  $(this).siblings(".custom-file-label").addClass("selected").html(fileName);
});

$("#genKey").click(function () {
  $(this).closest("form").attr("action", "/generate-key");
});

$("#genSign").click(function () {
  $(this).closest("form").attr("action", "/generate-sign");
});

$("#verify").click(function () {
  $(this).closest("form").attr("action", "/verify");
});

$("#downloadOutput").click(function () {
  $(this).closest("form").attr("action", "/download");
});

$("#intype").change(function () {
  if (this.value == "text") {
    $(".text").removeClass("d-none");
    $("#text").attr("required");
    $("#textfile").removeAttr("required");
    $(".file").addClass("d-none");
  } else {
    $(".file").removeClass("d-none");
    $("#textfile").attr("required");
    $("#text").removeAttr("required");
    $(".text").addClass("d-none");
  }
});

$("#instyle").change(function () {
  if (this.value == "intext") {
    $("#dsfile").removeAttr("required");
    $(".dsfile").addClass("d-none");
  } else {
    $(".dsfile").removeClass("d-none");
    $("#dsfile").attr("required");
  }
});
