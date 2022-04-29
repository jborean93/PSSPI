using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Language;

namespace PSSPI;

internal class PackageCompletor : IArgumentCompleter
{
    internal static SecPackageInfo[]? INSTALLED_PACKAGES = null;

    public IEnumerable<CompletionResult> CompleteArgument(string commandName, string parameterName,
        string wordToComplete, CommandAst commandAst, IDictionary fakeBoundParameters)
    {
        if (INSTALLED_PACKAGES == null)
        {
            try
            {
                INSTALLED_PACKAGES = SSPI.EnumerateSecurityPackages();
            }
            catch
            {
                INSTALLED_PACKAGES = Array.Empty<SecPackageInfo>();
            }
        }

        if (String.IsNullOrWhiteSpace(wordToComplete))
            wordToComplete = "";

        foreach (SecPackageInfo package in INSTALLED_PACKAGES)
        {
            if (package.Name.StartsWith(wordToComplete, true, CultureInfo.InvariantCulture))
            {
                yield return new CompletionResult(
                    package.Name,
                    package.Name,
                    CompletionResultType.ParameterValue,
                    package.Comment);
            }
        }
    }
}

public sealed class PackageOrString
{
    internal string Name { get; set; }

    public PackageOrString(SecPackageInfo info) => Name = info.Name;

    public PackageOrString(string name) => Name = name;
}

internal class SecBufferCompletor : IArgumentCompleter
{
    internal static string[] VALID_TYPES = Enum.GetNames(typeof(SecBufferType));

    public IEnumerable<CompletionResult> CompleteArgument(string commandName, string parameterName,
        string wordToComplete, CommandAst commandAst, IDictionary fakeBoundParameters)
    {
        if (String.IsNullOrWhiteSpace(wordToComplete))
            wordToComplete = "";

        foreach (string secType in VALID_TYPES)
        {
            if (secType.StartsWith(wordToComplete, true, CultureInfo.InvariantCulture))
            {
                yield return new CompletionResult(secType);
            }
        }
    }
}

public class SecBufferTransformer : ArgumentTransformationAttribute
{
    public override object Transform(EngineIntrinsics engineIntrinsics, object? inputData)
    {
        return TransformValues(inputData);
    }

    private ISecBuffer[] TransformValues(object? inputData)
    {
        if (inputData is PSObject objPS)
        {
            inputData = objPS.BaseObject;
        }

        List<ISecBuffer> transformed = new();
        if (inputData is IList objList && objList is not byte[])
        {
            foreach (object? obj in objList)
            {
                transformed.AddRange(TransformValues(obj));
            }

            return transformed.ToArray();
        }
        else
        {
            transformed.Add(TransformValue(inputData));
        }

        return transformed.ToArray();
    }

    private ISecBuffer TransformValue(object? inputData)
    {
        if (inputData is PSObject objPS)
        {
            inputData = objPS.BaseObject;
        }

        if (inputData is null)
        {
            return new SecurityBuffer(SecBufferType.SECBUFFER_TOKEN, SecBufferFlags.NONE, null);
        }
        else if (inputData is string objString)
        {
            SecBufferType secType = Enum.Parse<SecBufferType>(inputData?.ToString() ?? "", true);
            return new SecurityBuffer(secType, SecBufferFlags.NONE, null);
        }
        else if (inputData is ISecBuffer objSecBuffer)
        {
            return objSecBuffer;
        }
        else if (inputData is byte[] objByteArray)
        {
            return new SecurityBuffer(SecBufferType.SECBUFFER_TOKEN, SecBufferFlags.NONE, objByteArray);
        }

        throw new ArgumentTransformationMetadataException(
            $"Could not convert input '{inputData}' to a valid SecurityBuffer object.");
    }
}
