# -*- coding: utf-8 -*-
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core import Artifact
from com.pnfsoftware.jeb.core.input import FileInput
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType

from java.io import File

"""
Helper JEB script to generate Frida hooks
"""
class GenerateFridaHooks(IScript):
    frida_hooks = []
    frida_hook_file = u"""'use strict';
    // Usage: frida -U -f com.example.app -l generated_hook.js --no-pause
    Java.perform(function() {{
        {hooks}
    }});
    """
    frida_okhttp3_hook = u"""
        var okhttp3_CertificatePinner{idx} = Java.use('{java_class}');
        var findMatchingPins{idx} = okhttp3_CertificatePinner{idx}.{java_method}.overload('java.lang.String');
        findMatchingPins{idx}.implementation = function(hostname) {{
            console.log('[+] okhttp3.CertificatePinner.findMatchingPins(' + hostname + ') # {java_class}.{java_method}()');
            return findMatchingPins{idx}.call(this, ''); // replace hostname with empty string
        }}; """

    def run(self, ctx):
        # Hello world
        print(u"🔥 JEB scripting")
        # If the script is run in JEB GUI
        if isinstance(ctx, IGraphicalClientContext):
            project = ctx.getMainProject()
        else:  # assume command line & create a tmp project
            argv = ctx.getArguments()
            if len(argv) < 1:
                print('[-] Did you forget to provide the APK file?')
                return
            self.inputApk = argv[0]

            # Init engine
            engctx = ctx.getEnginesContext()
            if not engctx:
                print('[-] Back-end engines not initialized')
                return

            # Create a project
            project = engctx.loadProject('JebFridaHookProject')
            if not project:
                print('[-] Failed to open a new project')
                return
            
            # Add artifact to project
            artifact = Artifact('JebFridaHookArtifact', FileInput(File(self.inputApk)))
            project.processArtifact(artifact)


        # loop through all dex files in project & search
        for dex in project.findUnits(IDexUnit):
            # Generating hooks for OkHttp3
            for idx, result in enumerate(self.do_search(dex, "Certificate pinning failure!", ["Ljava/lang/String;"])):
                self.frida_hooks.append(
                    self.frida_okhttp3_hook.format(idx=idx, java_class=result.get("class"), java_method=result.get("method")))

        
        print(u"🔥 Fresh Frida Hooks")
        print("-" * 100)
        print(self.frida_hook_file.format(hooks="\n".join(self.frida_hooks)))
        print("-" * 100)


    def do_search(self, dex_unit, needle, params, retval = None):
        results = []
        # find string in DEX
        dex_index = dex_unit.findStringIndex(needle)
        # cross reference string, most probably used by the same class
        for ref in dex_unit.getCrossReferences(DexPoolType.STRING, dex_index):
            # get class name
            # getInternalAddress() returns something like Lcom/squareup/okhttp/CertificatePinner;->check(Ljava/lang/String;Ljava/util/List;)V+50h
            fqname = ref.getInternalAddress().split('->')[0]
            # get class (IDexClass)
            clazz = dex_unit.getClass(fqname)
            # From signature to class path
            # Lcom/squareup/okhttp/CertificatePinner; -> com.squareup.okhttp.CertificatePinner
            class2hook = clazz.getSignature()[1:-1].replace("/", ".")
            # loop through each method; check params & retval
            for method in clazz.getMethods():
                if retval is not None and method.getReturnType().getSignature() != retval: continue
                if self.list_cmp(params, [str(m.getSignature()) for m in method.getParameterTypes()]):
                    method2hook = method.getName()
                    results.append( {"class": class2hook, "method": method2hook})
        return results


    # is there a better way? PR/PM please!
    def list_cmp(self, a, b):
        if len(a) != len(b): return False
        for x, y in zip(a, b):
            if x != y: return False
        return True
