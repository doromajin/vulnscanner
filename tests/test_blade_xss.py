from vulnscanner.analyzers.blade_xss import BladeXSSAnalyzer


def _hits(src: str, path: str = "resources/views/show.blade.php"):
    return {(f.rule_id, f.severity.name) for f in BladeXSSAnalyzer().analyze(path, src)}


def test_request_data_printed_raw_is_high():
    assert ("BLADE-XSS-001", "HIGH") in _hits("<p>{!! request('bio') !!}</p>")
    assert ("BLADE-XSS-001", "HIGH") in _hits("<p>{!! $request->input('q') !!}</p>")


def test_escaped_echo_is_never_reported():
    assert _hits("<p>{{ request('bio') }} {{ $post->body }}</p>") == set()


def test_route_checks_in_class_attributes_are_not_xss():
    assert _hits("<li {!! (request()->is('users*') ? ' class=\"active\"' : '') !!}>") == set()


def test_form_helpers_escape_old_input():
    assert _hits("{!! Form::text('name', old('name'), ['class' => 'form-control']) !!}") == set()


def test_sanitised_or_framework_markup_is_ignored():
    src = "{!! e($post->body) !!} {!! clean($post->body) !!} {!! $items->links() !!} {!! csrf_field() !!}"
    assert _hits(src) == set()


def test_stored_content_variable_is_a_low_review_pointer():
    assert ("BLADE-XSS-002", "LOW") in _hits("<div>{!! $post->body !!}</div>")


def test_unrelated_variable_is_not_reported():
    assert _hits("<div>{!! $icon !!}</div>") == set()


def test_blade_comments_are_ignored():
    assert _hits("{{-- {!! request('x') !!} --}}") == set()


def test_only_blade_templates_are_analysed():
    assert not BladeXSSAnalyzer().supports("app/Http/Controllers/C.php")
    assert BladeXSSAnalyzer().supports("resources/views/a.blade.php")
