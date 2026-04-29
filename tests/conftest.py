import pathlib
import shutil

import pytest

import dragodis
from dragodis import UnsupportedError


@pytest.fixture
def global_datadir(tmp_path):
    """
    Creates temporary directory for the global /data folder in the same directory as conftest.
    Inspired by:
        github.com/gabrielcnr/pytest-datadir/issues/28
    """
    data_path = pathlib.Path(__file__).parent / "data"
    temp_path = tmp_path / "data"
    shutil.copytree(data_path, temp_path)
    return temp_path


@pytest.fixture
def disassembler_params(request, global_datadir):
    """
    Provides parametrized combinations for `open_program()`
    This fixture gets indirectly called by pytest_generate_tests.
    """
    if not hasattr(request, "param"):
        # If we don't have a param, we are making a disassembler for the doctests.
        # Set those to IDA with x86.
        backend = "ida"
        arch = "x86"
    else:
        backend, arch = request.param
    strings_path = global_datadir / f"strings_{arch}"

    if use_idalib := backend == "idalib":
        idapro = pytest.importorskip("idapro", reason="idalib not installed")
        backend = "ida"
        # NOTE: You may need to add '--capture=no' to the CLI to see the errors if IDA kills the process.
        idapro.enable_console_messages(True)

    return dict(
        file_path=str(strings_path),
        disassembler=backend,
        use_idalib=use_idalib,
    )


@pytest.fixture(scope="function")
def disassembler(disassembler_params) -> dragodis.Disassembler:
    """
    Generates a `dragodis.Disassembler` instance for given parameters.
    """
    try:
        with dragodis.open_program(**disassembler_params) as dis:
            yield dis
    except dragodis.NotInstalledError as e:
        pytest.skip(str(e))


BACKENDS = ["ida", "idalib", "ghidra", "vivisect"]
ARCHES = ["x86", "arm"]


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """
    Run test, then inspect the report. If the test failed because of
    UnsupportedError, mark it as xfail in the final report.
    """
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed:
        excinfo = call.excinfo
        if excinfo is not None and excinfo.type is UnsupportedError:
            report.outcome = "skipped"
            report.wasxfail = f"Unsupported: {excinfo.value}"
            report.longrepr = f"XFailed (converted from UnsupportedError): {excinfo.value}"


_param_cache = {}


def pytest_generate_tests(metafunc):
    """
    Generate parametrization for the "disassembler" fixture using the test function name
    to determine which combination of backends and architectures to use.
    """
    if "disassembler_params" in metafunc.fixturenames:
        # Filter specific backends and arches based on test function name.
        func_name = metafunc.function.__name__.casefold()
        keywords = func_name.split("_")

        # Include idalib if ida was requested.
        if "ida" in keywords and  "idalib" not in keywords:
            keywords.append("idalib")

        backends = [backend for backend in BACKENDS if backend in keywords]
        arches = [arch for arch in ARCHES if arch in keywords]

        # Since we default arch to only be x86, "all" can be used to signal all architectures.
        if not arches and "all" in keywords:
            arches = list(ARCHES)

        # Set defaults to be all backends and just the x86 sample.
        if not backends:
            backends = list(BACKENDS)
        if not arches:
            arches = ["x86"]

        # Parametrize the disassembler fixture based on filters.
        params = []
        for backend in backends:
            for arch in arches:
                # NOTE: We have to cache our parameters so we can reuse them in order to
                # ensure scoping is correct.
                # https://github.com/pytest-dev/pytest/issues/896
                key = (backend, arch)
                try:
                    param = _param_cache[key]
                except KeyError:
                    param = pytest.param(key, id=f"{backend}-{arch}", marks=[
                        getattr(pytest.mark, backend), getattr(pytest.mark, arch)
                    ])
                    _param_cache[key] = param
                params.append(param)
        metafunc.parametrize("disassembler_params", params, indirect=True)


def pytest_make_parametrize_id(config, val, argname):
    """
    Hook id creation to convert addresses into hex.
    """
    if "address" in argname:
        return hex(val)
