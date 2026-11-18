from vulnscanner.analyzers.missing_auth import MissingAuthAnalyzer


def _auth(src: str):
    return [(f.rule_id, f.severity.name) for f in MissingAuthAnalyzer().analyze("app/views.py", src)]


def test_stateless_post_handler_is_low():
    src = "@require_POST\ndef preview(request):\n    f = Form(request.POST)\n    return render(request, 'x.html', {'f': f})\n"
    assert _auth(src) == [("AUTH-001", "LOW")]


def test_post_handler_that_deletes_data_stays_high():
    src = "@require_POST\ndef kill(request, pk):\n    Item.objects.filter(pk=pk).delete()\n    return redirect('/')\n"
    assert _auth(src) == [("AUTH-001", "HIGH")]


def test_webhook_check_is_limited_to_its_own_function_body():
    src = ("@csrf_exempt\n@require_POST\ndef hook(request):\n    return HttpResponse()\n\n"
           "def other(request):\n    return request.user\n")
    assert _auth(src) == [("AUTH-001", "LOW")]
