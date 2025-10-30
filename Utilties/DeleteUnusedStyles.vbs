' When I wrote V3, I had the idea of using the MS Word master document feature.
' After hours of therapy, I was healed of this affliction. 
' The following code removes unused styles that the master doc feature pushes into your doc
' when you add it to a master and select "yes to all" on the styles dialog.

Sub DeleteUnusedStyles()
    Dim oStyle As Style
    Dim oRng As Range
    Dim sStylesToDelete As String
    Dim totalStyles As Long
    Dim currentStyleIndex As Long
    Dim styleInUse As Boolean

    totalStyles = ActiveDocument.Styles.Count
    currentStyleIndex = 0

    ' Loop through all styles in the document
    For Each oStyle In ActiveDocument.Styles
        currentStyleIndex = currentStyleIndex + 1

        ' Update status bar with progress
        StatusBar = "Checking styles... " & Format(currentStyleIndex / totalStyles, "0%") & " complete"

        If Not oStyle.BuiltIn Then
            styleInUse = False
            ' Check the main body and all headers/footers
            For Each oRng In ActiveDocument.StoryRanges
                With oRng.Find
                    .ClearFormatting
                    .Style = oStyle
                    If .Execute Then
                        styleInUse = True
                        Exit For
                    End If
                End With
            Next oRng

            If Not styleInUse Then
                sStylesToDelete = sStylesToDelete & oStyle.NameLocal & vbCr
            End If
        End If
    Next oStyle

    StatusBar = "Review complete."

    If sStylesToDelete <> "" Then
        MsgBox "The following styles are not in use and will be deleted:" & vbCr & sStylesToDelete, vbQuestion, "Unused Styles Found"

        On Error Resume Next
        currentStyleIndex = 0

        For Each oStyle In ActiveDocument.Styles
            currentStyleIndex = currentStyleIndex + 1
            StatusBar = "Deleting unused styles... " & Format(currentStyleIndex / totalStyles, "0%") & " complete"

            If Not oStyle.BuiltIn Then
                If InStr(sStylesToDelete, oStyle.NameLocal) > 0 Then
                    oStyle.Delete
                End If
            End If
        Next oStyle
        On Error GoTo 0

        StatusBar = "Deletion complete."
        MsgBox "Unused styles have been removed.", vbInformation
    Else
        MsgBox "No unused styles were found.", vbInformation
    End If

    StatusBar = ""
End Sub
