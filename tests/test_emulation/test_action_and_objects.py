from rugosa.emulation.emulator import Emulator
from rugosa.emulation import actions, objects


def test_objects_and_actions(disassembler):
    """Test the objects and actions feature."""
    emulator = Emulator(disassembler)

    # NOTE: We are just going to fake adding actions since our strings.exe example
    # doesn't perform any actions.
    offset = 0x1234
    ctx = emulator.new_context()
    ctx.ip = offset
    assert not ctx.actions
    handle = ctx.objects.alloc()
    assert handle == 0x80
    ctx.actions.add(actions.FileOpened(ip=offset-3, handle=handle, path=r"C:\dummy\path", mode="w"))
    ctx.actions.add(actions.FileWritten(ip=offset-2, handle=handle, data=b"first bytes\n"))
    # Throw in some other random actions for good measure.
    ctx.actions.add(actions.CommandExecuted(ip=offset-6, command="hello"))
    ctx.actions.add(actions.FileWritten(ip=offset-1, handle=handle, data=b"second bytes"))
    assert ctx.objects
    assert len(ctx.objects) == 1
    # Casting is necessary if emulator is teleported.
    assert list(ctx.objects.handles) == [handle]
    file_obj = ctx.objects[handle]
    assert file_obj
    assert file_obj.handle == handle
    assert isinstance(file_obj, objects.File)
    assert file_obj.path == r"C:\dummy\path"
    assert file_obj.mode == "w"
    assert file_obj.data == b"first bytes\nsecond bytes"
    assert file_obj.closed is False
    assert list(file_obj.references) == [offset-3, offset-2, offset-1]

    # Now test if we can detect when the right file is closed.
    # NOTE: We have to regrab the object for changes to take affect.
    sec_handle = ctx.objects.alloc()
    ctx.actions.add(actions.FileClosed(ip=offset, handle=sec_handle))
    assert len(ctx.objects) == 2
    assert ctx.objects[handle].closed is False
    ctx.actions.add(actions.FileClosed(ip=offset, handle=handle))
    assert ctx.objects[handle].closed is True
    assert list(ctx.objects.handles) == [handle, sec_handle]
