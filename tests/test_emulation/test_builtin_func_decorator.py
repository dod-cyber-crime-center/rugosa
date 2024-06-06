from rugosa.emulation.call_hooks import _builtin_func_registrar


def test_builtin_func():
    
    hooks = {}
    builtin_func = _builtin_func_registrar(hooks)
    
    @builtin_func("Name1", num_args=25)
    @builtin_func("Name2", num_args=15)
    @builtin_func(num_args=10)
    @builtin_func("Name4")
    def func_a():
        ...
        
    @builtin_func
    def func_b():
        ...
    
    assert "func_b" in hooks
    
    name = "Name1".lower()
    assert name in hooks
    assert "func_a" in hooks
    assert func_a.num_args(name) == 25
    assert func_a.num_args("name2") == 15
    assert func_a.num_args("func_a") == 10
    assert func_a.num_args("name4") is None
    
